package br.com.atesta.assinatura;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class SignatureValidationService {
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public SignatureValidationResult validate(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            return SignatureValidationResult.error("Arquivo PDF não recebido.");
        }

        String name = file.getOriginalFilename() == null ? "" : file.getOriginalFilename().toLowerCase();
        String type = file.getContentType() == null ? "" : file.getContentType().toLowerCase();
        if (!name.endsWith(".pdf") && !type.contains("pdf")) {
            return SignatureValidationResult.error("Envie um arquivo PDF para validação de assinatura.");
        }

        try {
            byte[] pdf = file.getBytes();
            SignatureValidationResult out = new SignatureValidationResult();
            out.ok = true;
            out.validationLevel = "demoiselle_pades_poc";

            try (PDDocument document = PDDocument.load(pdf)) {
                List<PDSignature> signatures = document.getSignatureDictionaries();
                out.hasSignature = signatures != null && !signatures.isEmpty();

                if (!out.hasSignature) {
                    out.result = "not_signed";
                    out.valid = false;
                    out.icpBrasil = false;
                    out.standard = null;
                    out.message = "Assinatura digital não localizada no PDF.";
                    return out;
                }

                out.standard = "PAdES provável";
                int idx = 1;
                boolean anyValid = false;
                boolean anyIcp = false;
                boolean allChecked = true;
                boolean anyInvalid = false;

                for (PDSignature pdSignature : signatures) {
                    SignatureInfo info = extractBasicSignatureInfo(pdSignature, idx++);
                    out.signatures.add(info);

                    byte[] contents = safeGetContents(pdSignature, pdf);
                    byte[] signedContent = safeGetSignedContent(pdSignature, pdf);

                    enrichWithCmsCertificateInfo(info, contents);

                    DemoiselleOutcome demoiselle = tryValidateWithDemoiselle(signedContent, contents, info);
                    info.demoiselleChecked = demoiselle.checked;
                    info.demoiselleValid = demoiselle.valid;
                    if (demoiselle.icpBrasil != null) {
                        info.icpBrasil = demoiselle.icpBrasil;
                    }

                    if (!demoiselle.checked) {
                        allChecked = false;
                        out.warnings.add("A assinatura " + info.index + " foi detectada, mas a validação Demoiselle não foi concluída: " + demoiselle.message);
                    } else if (Boolean.TRUE.equals(demoiselle.valid)) {
                        anyValid = true;
                        if (Boolean.TRUE.equals(info.icpBrasil)) {
                            anyIcp = true;
                        }
                    } else {
                        anyInvalid = true;
                    }
                }

                if (anyValid && anyIcp) {
                    out.result = "valid_icp_brasil";
                    out.valid = true;
                    out.icpBrasil = true;
                    out.message = "Assinatura PAdES validada pelo Demoiselle Signer, com indício de certificado ICP-Brasil.";
                } else if (anyValid) {
                    out.result = "valid_signature_unconfirmed_icp";
                    out.valid = true;
                    out.icpBrasil = false;
                    out.message = "Assinatura validada pelo Demoiselle Signer, mas a cadeia ICP-Brasil não foi confirmada automaticamente nesta prova de conceito.";
                } else if (anyInvalid && allChecked) {
                    out.result = "invalid_signature";
                    out.valid = false;
                    out.icpBrasil = false;
                    out.message = "Assinatura detectada, mas a validação retornou erro ou restrição.";
                } else {
                    out.result = "signature_detected";
                    out.valid = null;
                    out.icpBrasil = null;
                    out.message = "Assinatura digital detectada. A tentativa de validação Demoiselle não foi conclusiva nesta prova de conceito.";
                    out.warnings.add("Não use este retorno como validação ICP-Brasil definitiva sem teste com amostra representativa e conferência do relatório técnico.");
                }

                return out;
            }
        } catch (Exception e) {
            return SignatureValidationResult.error("Falha ao validar assinatura: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }
    }

    private SignatureInfo extractBasicSignatureInfo(PDSignature sig, int index) {
        SignatureInfo info = new SignatureInfo();
        info.index = index;
        info.name = sig.getName();
        info.reason = sig.getReason();
        info.location = sig.getLocation();
        info.contactInfo = sig.getContactInfo();
        info.filter = sig.getFilter();
        info.subFilter = sig.getSubFilter();
        info.padesLikely = sig.getSubFilter() != null && sig.getSubFilter().toLowerCase().contains("etsi");
        Date signDate = sig.getSignDate() == null ? null : sig.getSignDate().getTime();
        if (signDate != null) {
            info.signDate = DATE_FORMAT.format(signDate.toInstant().atZone(ZoneId.systemDefault()));
        }
        return info;
    }

    private byte[] safeGetContents(PDSignature sig, byte[] pdf) throws Exception {
        return sig.getContents(new ByteArrayInputStream(pdf));
    }

    private byte[] safeGetSignedContent(PDSignature sig, byte[] pdf) throws Exception {
        return sig.getSignedContent(new ByteArrayInputStream(pdf));
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void enrichWithCmsCertificateInfo(SignatureInfo info, byte[] contents) {
        try {
            if (contents == null || contents.length == 0) {
                return;
            }
            CMSSignedData cms = new CMSSignedData(contents);
            SignerInformationStore signers = cms.getSignerInfos();
            Collection<SignerInformation> signerInfos = signers.getSigners();
            Store certStore = cms.getCertificates();
            CertificateFactory factory = CertificateFactory.getInstance("X.509");

            for (SignerInformation signer : signerInfos) {
                Collection matches = certStore.getMatches(signer.getSID());
                if (!matches.isEmpty()) {
                    Object holder = matches.iterator().next();
                    Method getEncoded = holder.getClass().getMethod("getEncoded");
                    byte[] certBytes = (byte[]) getEncoded.invoke(holder);
                    X509Certificate cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
                    info.certificateSubject = cert.getSubjectX500Principal().getName();
                    info.certificateIssuer = cert.getIssuerX500Principal().getName();
                    info.certificateNotBefore = DATE_FORMAT.format(cert.getNotBefore().toInstant().atZone(ZoneId.systemDefault()));
                    info.certificateNotAfter = DATE_FORMAT.format(cert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()));
                    if (looksLikeIcpBrasil(cert)) {
                        info.icpBrasil = true;
                    }
                    return;
                }
            }
        } catch (Exception e) {
            info.validatorWarnings.add("Não foi possível extrair certificado do CMS: " + e.getMessage());
        }
    }

    private boolean looksLikeIcpBrasil(X509Certificate cert) {
        if (cert == null) return false;
        String subject = cert.getSubjectX500Principal().getName().toUpperCase();
        String issuer = cert.getIssuerX500Principal().getName().toUpperCase();
        return subject.contains("ICP-BRASIL") || issuer.contains("ICP-BRASIL") || issuer.contains("ICP BRASIL") || subject.contains("ICP BRASIL");
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private DemoiselleOutcome tryValidateWithDemoiselle(byte[] signedContent, byte[] signature, SignatureInfo info) {
        DemoiselleOutcome outcome = new DemoiselleOutcome();
        try {
            if (signedContent == null || signedContent.length == 0 || signature == null || signature.length == 0) {
                outcome.checked = false;
                outcome.valid = false;
                outcome.message = "conteúdo assinado ou assinatura não extraídos do PDF";
                return outcome;
            }

            Class<?> checkerClass = Class.forName("org.demoiselle.signer.policy.impl.pades.pkcs7.impl.PAdESChecker");
            Object checker = checkerClass.getDeclaredConstructor().newInstance();
            Method method = checkerClass.getMethod("checkDetachedSignature", byte[].class, byte[].class);
            Object result = method.invoke(checker, signedContent, signature);

            outcome.checked = true;
            outcome.valid = true;
            outcome.message = "Demoiselle retornou resultado de validação.";

            if (result instanceof List list) {
                for (Object signatureInformation : list) {
                    readDemoiselleSignatureInformation(signatureInformation, info);
                }
            }

            outcome.icpBrasil = Boolean.TRUE.equals(info.icpBrasil);
            return outcome;
        } catch (ClassNotFoundException e) {
            outcome.checked = false;
            outcome.valid = false;
            outcome.message = "classe do Demoiselle Signer não encontrada no classpath";
            return outcome;
        } catch (Exception e) {
            outcome.checked = true;
            outcome.valid = false;
            outcome.message = e.getClass().getSimpleName() + ": " + safeMessage(e);
            info.validatorErrors.add("Demoiselle: " + outcome.message);
            return outcome;
        }
    }

    private void readDemoiselleSignatureInformation(Object signatureInformation, SignatureInfo info) {
        if (signatureInformation == null) return;
        tryReadList(signatureInformation, "getValidatorErrors", info.validatorErrors);
        tryReadList(signatureInformation, "getValidatorWarnins", info.validatorWarnings);
        tryReadList(signatureInformation, "getValidatorWarnings", info.validatorWarnings);

        Object invalid = tryInvoke(signatureInformation, "isInvalidSignature");
        if (invalid instanceof Boolean && Boolean.TRUE.equals(invalid)) {
            info.demoiselleValid = false;
        }

        Object icpCert = tryInvoke(signatureInformation, "getIcpBrasilcertificate");
        if (icpCert != null) {
            info.icpBrasil = true;
        }
    }

    @SuppressWarnings("rawtypes")
    private void tryReadList(Object target, String methodName, List<String> destination) {
        try {
            Object value = tryInvoke(target, methodName);
            if (value instanceof Iterable iterable) {
                for (Object item : iterable) {
                    if (item != null) destination.add(String.valueOf(item));
                }
            }
        } catch (Exception ignored) {
            // método opcional em versões diferentes do Demoiselle
        }
    }

    private Object tryInvoke(Object target, String methodName) {
        try {
            Method m = target.getClass().getMethod(methodName);
            return m.invoke(target);
        } catch (Exception ignored) {
            return null;
        }
    }

    private String safeMessage(Exception e) {
        Throwable t = e.getCause() != null ? e.getCause() : e;
        return t.getMessage() == null ? t.toString() : t.getMessage();
    }

    private static class DemoiselleOutcome {
        boolean checked;
        Boolean valid;
        Boolean icpBrasil;
        String message;
    }
}
