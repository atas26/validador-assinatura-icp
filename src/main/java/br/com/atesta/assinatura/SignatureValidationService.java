package br.com.atesta.assinatura;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class SignatureValidationService {
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    /*
     * Etapa 5:
     * A validação da cadeia usa âncoras confiáveis locais da ICP-Brasil.
     *
     * Opção 1:
     * Colocar os certificados da AC-Raiz ICP-Brasil em:
     * src/main/resources/icp-brasil/trust-anchors/
     *
     * Nomes aceitos:
     * ac-raiz-icp-brasil-v1.cer ... ac-raiz-icp-brasil-v13.cer
     * ac-raiz-icp-brasil-v1.crt ... ac-raiz-icp-brasil-v13.crt
     * ac-raiz-icp-brasil-v1.pem ... ac-raiz-icp-brasil-v13.pem
     *
     * Opção 2:
     * Informar um diretório por variável de ambiente:
     * ICP_TRUST_ANCHORS_DIR=/caminho/dos/certificados
     */
    private static final String TRUST_ANCHOR_RESOURCE_DIR = "icp-brasil/trust-anchors/";
    private static final ASN1ObjectIdentifier ID_AA_SIGNATURE_TIMESTAMP_TOKEN = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14");
    private static final ASN1ObjectIdentifier ID_AA_ETS_SIG_POLICY_ID = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.15");

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
            initializeDefaults(out);

            out.ok = true;
            out.validationLevel = "pades_b_chain_crl_validation";

            try (PDDocument document = PDDocument.load(pdf)) {
                List<PDSignature> signatures = document.getSignatureDictionaries();
                out.hasSignature = signatures != null && !signatures.isEmpty();

                if (!out.hasSignature) {
                    out.result = "not_signed";
                    out.valid = false;
                    out.icpBrasil = false;
                    out.standard = null;
                    out.message = "Assinatura digital não localizada no PDF.";
                    out.signatureIntegrityValid = false;
                    out.byteRangeValid = false;
                    out.finalDocumentCovered = false;
                    out.chainValid = false;
                    return out;
                }

                int idx = 1;
                boolean anyValid = false;
                boolean anyIcp = false;
                boolean anyPades = false;
                boolean allChecked = true;
                boolean anyInvalid = false;
                boolean allByteRangesWellFormed = true;
                boolean anyByteRangeCoversWholeFile = false;
                boolean anyFinalDocumentAcceptable = false;
                boolean anySignatureWithoutFinalCoverage = false;
                boolean anyPostSignatureUpdateDetected = false;
                boolean anyPostSignatureUpdateAccepted = false;
                boolean anyPostSignatureUpdateUnknown = false;
                boolean anyChainValid = false;
                boolean anyChainChecked = false;
                boolean anyRevocationChecked = false;
                boolean anyNotRevoked = false;
                boolean anyRevoked = false;
                boolean anyTimestampPresent = false;
                boolean anyTimestampValid = false;
                boolean anyPolicyDeclared = false;
                boolean anyPolicyRecognized = false;

                for (PDSignature pdSignature : signatures) {
                    SignatureInfo info = extractBasicSignatureInfo(pdSignature, idx++);
                    out.signatures.add(info);

                    boolean byteRangeWellFormed = isByteRangePresentAndWellFormed(pdSignature, pdf.length);
                    boolean byteRangeCoversDocument = byteRangeWellFormed && byteRangeCoversWholeFile(pdSignature, pdf.length);
                    PostSignatureUpdateAnalysis postSignatureUpdate = analyzePostSignatureUpdate(pdSignature, pdf);

                    if (!byteRangeWellFormed) {
                        allByteRangesWellFormed = false;
                        info.validatorErrors.add("ByteRange ausente ou malformado.");
                    } else if (byteRangeCoversDocument) {
                        anyByteRangeCoversWholeFile = true;
                        anyFinalDocumentAcceptable = true;
                    } else {
                        anySignatureWithoutFinalCoverage = true;
                        anyPostSignatureUpdateDetected = anyPostSignatureUpdateDetected || postSignatureUpdate.detected;

                        if (postSignatureUpdate.detected && (out.postSignatureUpdateType == null || out.postSignatureUpdateType.isBlank())) {
                            out.postSignatureUpdateType = postSignatureUpdate.type;
                            out.postSignatureUpdateMessage = postSignatureUpdate.message;
                            out.postSignatureUpdateBytes = postSignatureUpdate.bytes;
                        }

                        if (postSignatureUpdate.accepted) {
                            anyPostSignatureUpdateAccepted = true;
                            anyFinalDocumentAcceptable = true;
                            info.validatorWarnings.add(postSignatureUpdate.message);
                        } else {
                            anyPostSignatureUpdateUnknown = true;
                            info.validatorWarnings.add(postSignatureUpdate.message);
                        }
                    }

                    if (isPadesSubFilter(pdSignature)) {
                        anyPades = true;
                    }

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
                        out.warnings.add("A assinatura " + info.index + " foi detectada, mas a validação técnica não foi concluída: " + demoiselle.message);
                    } else if (Boolean.TRUE.equals(demoiselle.valid)) {
                        anyValid = true;
                        if (Boolean.TRUE.equals(info.icpBrasil)) {
                            anyIcp = true;
                        }
                    } else {
                        anyInvalid = true;
                    }

                    TimestampValidationOutcome timestamp = inspectSignatureTimestamp(contents, info);
                    if (timestamp.present) {
                        anyTimestampPresent = true;
                        out.timestampPresent = true;
                        if (timestamp.authority != null && (out.timestampAuthority == null || out.timestampAuthority.isBlank())) {
                            out.timestampAuthority = timestamp.authority;
                        }
                        if (timestamp.time != null && (out.timestampTime == null || out.timestampTime.isBlank())) {
                            out.timestampTime = timestamp.time;
                        }
                        if (timestamp.valid) {
                            anyTimestampValid = true;
                            out.timestampValid = true;
                            info.validatorWarnings.add(timestamp.message);
                        } else {
                            out.timestampValid = false;
                            info.validatorWarnings.add(timestamp.message);
                        }
                    }

                    PolicyValidationOutcome policy = inspectSignaturePolicy(contents, info);
                    if (policy.declared) {
                        anyPolicyDeclared = true;
                        if (policy.recognized) {
                            anyPolicyRecognized = true;
                        }
                        if (out.policyOid == null || out.policyOid.isBlank()) {
                            out.policyOid = policy.oid;
                        }
                        if (out.policyName == null || out.policyName.isBlank()) {
                            out.policyName = policy.name;
                        }
                        info.validatorWarnings.add(policy.message);
                    } else if (policy.message != null && !policy.message.isBlank()) {
                        info.validatorWarnings.add(policy.message);
                    }

                    Date validationDate = pdSignature.getSignDate() == null ? new Date() : pdSignature.getSignDate().getTime();
                    ChainValidationOutcome chain = validateIcpBrasilChain(contents, validationDate);

                    if (chain.checked) {
                        anyChainChecked = true;
                    }

                    if (chain.valid) {
                        anyChainValid = true;
                        anyIcp = true;
                        info.icpBrasil = true;
                    }

                    if (chain.trustAnchor != null && (out.trustAnchor == null || out.trustAnchor.isBlank())) {
                        out.trustAnchor = chain.trustAnchor;
                    }

                    if (chain.chainPath != null && !chain.chainPath.isEmpty() && out.chainPath.isEmpty()) {
                        out.chainPath.addAll(chain.chainPath);
                    }

                    if (chain.message != null && !chain.message.isBlank()) {
                        if (chain.valid) {
                            info.validatorWarnings.add(chain.message);
                        } else if (chain.checked) {
                            info.validatorErrors.add(chain.message);
                        } else {
                            info.validatorWarnings.add(chain.message);
                        }
                    }

                    RevocationOutcome revocation = checkRevocationByOcspThenCrl(contents);

                    if (revocation.checked) {
                        anyRevocationChecked = true;
                        out.revocationChecked = true;
                        out.revocationMethod = revocation.method == null || revocation.method.isBlank() ? "CRL" : revocation.method;

                        if (out.ocspUrl == null || out.ocspUrl.isBlank()) {
                            out.ocspUrl = revocation.ocspUrl;
                        }
                        if (out.ocspStatus == null || out.ocspStatus.isBlank()) {
                            out.ocspStatus = revocation.ocspStatus;
                        }
                        if (out.ocspResponder == null || out.ocspResponder.isBlank()) {
                            out.ocspResponder = revocation.ocspResponder;
                        }
                        if (out.ocspProducedAt == null || out.ocspProducedAt.isBlank()) {
                            out.ocspProducedAt = revocation.ocspProducedAt;
                        }
                        if (out.ocspThisUpdate == null || out.ocspThisUpdate.isBlank()) {
                            out.ocspThisUpdate = revocation.ocspThisUpdate;
                        }
                        if (out.ocspNextUpdate == null || out.ocspNextUpdate.isBlank()) {
                            out.ocspNextUpdate = revocation.ocspNextUpdate;
                        }

                        if (out.crlUrl == null || out.crlUrl.isBlank()) {
                            out.crlUrl = revocation.crlUrl;
                        }
                        if (out.crlIssuer == null || out.crlIssuer.isBlank()) {
                            out.crlIssuer = revocation.crlIssuer;
                        }
                        if (out.crlThisUpdate == null || out.crlThisUpdate.isBlank()) {
                            out.crlThisUpdate = revocation.thisUpdate;
                        }
                        if (out.crlNextUpdate == null || out.crlNextUpdate.isBlank()) {
                            out.crlNextUpdate = revocation.nextUpdate;
                        }

                        if (revocation.revoked) {
                            anyRevoked = true;
                            out.revoked = true;
                            out.revocationDate = revocation.revocationDate;
                            out.revocationReason = revocation.revocationReason;
                            info.validatorErrors.add(revocation.message);
                        } else {
                            anyNotRevoked = true;
                            if (!Boolean.TRUE.equals(out.revoked)) {
                                out.revoked = false;
                            }
                            info.validatorWarnings.add(revocation.message);
                        }
                    } else {
                        info.validatorWarnings.add(revocation.message);
                    }
                }

                boolean byteRangesWellFormed = allByteRangesWellFormed;
                boolean finalDocumentCovered = anyByteRangeCoversWholeFile;
                boolean finalDocumentAcceptable = anyFinalDocumentAcceptable;

                out.byteRangeValid = byteRangesWellFormed;
                out.finalDocumentCovered = finalDocumentCovered;
                out.finalDocumentAcceptable = finalDocumentAcceptable;
                out.postSignatureUpdateDetected = anyPostSignatureUpdateDetected;
                out.postSignatureUpdateAccepted = anyPostSignatureUpdateAccepted;
                out.signatureIntegrityValid = anyValid && byteRangesWellFormed;
                out.chainValid = anyChainValid;
                out.timestampPresent = anyTimestampPresent;
                if (anyTimestampPresent && !anyTimestampValid && out.timestampValid == null) {
                    out.timestampValid = false;
                }
                out.policyDeclared = anyPolicyDeclared;
                out.policyRecognized = anyPolicyRecognized;
                out.standard = anyPades ? "PAdES-B" : "Assinatura PDF";
                if ("dss_lt_upgrade_no_tsa".equals(out.postSignatureUpdateType) || "dss_ltv_update".equals(out.postSignatureUpdateType)) {
                    out.standard = "PAdES-B com DSS";
                }
                if (anyTimestampValid) {
                    out.standard = out.standard != null && out.standard.contains("DSS") ? "PAdES-T com DSS" : "PAdES-T";
                    out.validationLevel = "pades_t_chain_revocation_validation";
                }

                if (!byteRangesWellFormed) {
                    out.result = "invalid_signature_byte_range";
                    out.valid = false;
                    out.icpBrasil = anyIcp;
                    out.signatureIntegrityValid = false;
                    out.finalDocumentCovered = false;
                    out.message = "Assinatura detectada, mas o ByteRange está ausente ou malformado.";
                    return out;
                }

                if (!finalDocumentAcceptable) {
                    out.result = "signature_valid_but_pdf_not_fully_covered";
                    out.valid = false;
                    out.icpBrasil = anyIcp;
                    out.message = anySignatureWithoutFinalCoverage
                            ? "Assinatura validada sobre a revisão assinada, mas a atualização incremental posterior não foi classificada como técnica permitida."
                            : "Assinatura detectada, mas nenhuma assinatura cobre o arquivo PDF final analisado.";

                    if (anyPostSignatureUpdateUnknown) {
                        out.warnings.add("Foi detectada atualização incremental posterior à revisão assinada. A ferramenta não conseguiu classificá-la como atualização técnica de validação, carimbo do tempo ou assinatura adicional. Para aceitação automática, o conteúdo posterior deve ser analisado tecnicamente.");
                    } else {
                        out.warnings.add("Para aceitação automática, o PDF final deve estar coberto por assinatura válida ou por atualização incremental técnica classificada.");
                    }
                    return out;
                }

                if (anyValid && anyIcp && anyChainValid && anyRevoked) {
                    out.result = "certificate_revoked";
                    out.valid = false;
                    out.icpBrasil = true;
                    out.revocationChecked = true;
                    out.revoked = true;
                    out.message = "Assinatura PAdES-B validada, com cadeia ICP-Brasil reconhecida, mas o certificado consta como revogado na LCR consultada.";
                } else if (anyValid && anyIcp && anyChainValid && anyRevocationChecked && anyNotRevoked) {
                    out.result = finalDocumentCovered
                            ? "valid_icp_brasil_chain_crl"
                            : "valid_icp_brasil_chain_crl_with_permitted_incremental_update";
                    out.valid = true;
                    out.icpBrasil = true;
                    out.revocationChecked = true;
                    out.revoked = false;
                    out.message = finalDocumentCovered
                            ? "Assinatura PAdES-B validada. Certificado ICP-Brasil identificado. Cadeia de certificação validada até âncora confiável da ICP-Brasil. Consulta de revogação realizada sem identificação de revogação."
                            : "Assinatura PAdES-B validada sobre a revisão assinada. Certificado ICP-Brasil identificado. Cadeia validada até âncora confiável da ICP-Brasil. Consulta de revogação realizada sem identificação de revogação. A atualização incremental posterior foi classificada como técnica permitida.";
                    if (!finalDocumentCovered && anyPostSignatureUpdateAccepted) {
                        out.warnings.add("O PDF final contém atualização incremental posterior à assinatura. A atualização foi classificada como técnica permitida: " + safeText(out.postSignatureUpdateType) + ".");
                    }
                    if (anyTimestampValid) {
                        out.warnings.add("Carimbo do tempo de assinatura localizado e validado.");
                    } else {
                        out.warnings.add("TSA não localizada ou não validada. A classificação permanece como " + safeText(out.standard) + ".");
                    }

                    if (anyPolicyDeclared) {
                        out.warnings.add("Política de assinatura declarada no pacote assinado: " + safeText(out.policyName) + (out.policyOid == null ? "." : " (OID " + out.policyOid + ")."));
                    } else {
                        out.warnings.add("Política de assinatura ICP-Brasil tipificada não declarada no pacote assinado.");
                    }
                } else if (anyValid && anyIcp && anyChainValid) {
                    out.result = "valid_icp_brasil_chain_revocation_not_checked";
                    out.valid = null;
                    out.icpBrasil = true;
                    out.revocationChecked = false;
                    out.message = "Assinatura PAdES-B validada e cadeia ICP-Brasil reconhecida, mas a consulta de revogação por OCSP ou LCR não foi concluída.";
                    out.warnings.add("Sem consulta de revogação, o resultado não deve ser tratado como conformidade plena da assinatura.");
                } else if (anyValid && anyIcp && !anyChainValid) {
                    out.result = anyChainChecked ? "signature_valid_chain_invalid" : "signature_valid_chain_not_checked";
                    out.valid = null;
                    out.icpBrasil = true;
                    out.message = anyChainChecked
                            ? "Assinatura PAdES-B validada e certificado ICP-Brasil identificado, mas a cadeia de certificação não foi validada até âncora confiável da ICP-Brasil."
                            : "Assinatura PAdES-B validada e certificado ICP-Brasil identificado, mas a cadeia de certificação não foi verificada por ausência de âncora confiável local.";
                    out.warnings.add("Para concluir a etapa de cadeia, cadastre os certificados oficiais da AC-Raiz ICP-Brasil no projeto.");
                } else if (anyValid) {
                    out.result = "valid_signature_unconfirmed_icp";
                    out.valid = true;
                    out.icpBrasil = false;
                    out.message = "Assinatura validada, mas a identificação como certificado ICP-Brasil não foi confirmada automaticamente.";
                    out.warnings.add("Cadeia integral, revogação por LCR ou OCSP e TSA devem ser concluídas para validação plena. Política de assinatura será informada quando declarada no pacote assinado.");
                } else if (anyInvalid && allChecked) {
                    out.result = "invalid_signature";
                    out.valid = false;
                    out.icpBrasil = false;
                    out.signatureIntegrityValid = false;
                    out.message = "Assinatura detectada, mas a validação técnica retornou erro ou restrição.";
                } else {
                    out.result = "signature_detected_not_conclusive";
                    out.valid = null;
                    out.icpBrasil = null;
                    out.signatureIntegrityValid = null;
                    out.message = "Assinatura digital detectada, mas a validação técnica não foi conclusiva.";
                    out.warnings.add("Sem validação conclusiva, o resultado não deve ser tratado como conformidade da assinatura.");
                }

                return out;
            }
        } catch (Exception e) {
            return SignatureValidationResult.error("Falha ao validar assinatura: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }
    }

    private void initializeDefaults(SignatureValidationResult out) {
        out.ok = false;
        out.result = "not_processed";

        out.hasSignature = false;
        out.valid = null;
        out.icpBrasil = null;

        out.standard = null;
        out.validationLevel = "pades_b_chain_crl_validation";
        out.message = null;

        out.signatureIntegrityValid = null;
        out.byteRangeValid = null;
        out.finalDocumentCovered = null;
        out.finalDocumentAcceptable = null;
        out.postSignatureUpdateDetected = false;
        out.postSignatureUpdateAccepted = false;
        out.postSignatureUpdateType = null;
        out.postSignatureUpdateBytes = null;
        out.postSignatureUpdateMessage = null;

        out.chainValid = null;
        out.trustAnchor = null;

        out.revocationChecked = false;
        out.revocationMethod = null;
        out.revoked = null;
        out.crlUrl = null;
        out.crlIssuer = null;
        out.crlThisUpdate = null;
        out.crlNextUpdate = null;
        out.revocationDate = null;
        out.revocationReason = null;
        out.ocspUrl = null;
        out.ocspStatus = null;
        out.ocspResponder = null;
        out.ocspProducedAt = null;
        out.ocspThisUpdate = null;
        out.ocspNextUpdate = null;

        out.timestampPresent = false;
        out.timestampValid = null;
        out.timestampAuthority = null;
        out.timestampTime = null;

        out.policyOid = null;
        out.policyName = null;
        out.policyDeclared = false;
        out.policyRecognized = false;
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
        info.padesLikely = isPadesSubFilter(sig);

        Date signDate = sig.getSignDate() == null ? null : sig.getSignDate().getTime();
        if (signDate != null) {
            info.signDate = DATE_FORMAT.format(signDate.toInstant().atZone(ZoneId.systemDefault()));
        }

        return info;
    }

    private boolean isPadesSubFilter(PDSignature sig) {
        if (sig == null || sig.getSubFilter() == null) {
            return false;
        }

        String subFilter = sig.getSubFilter().toLowerCase();

        return subFilter.contains("etsi.cades.detached")
                || subFilter.contains("adbe.pkcs7.detached")
                || subFilter.contains("adbe.pkcs7.sha1");
    }

    private boolean isByteRangePresentAndWellFormed(PDSignature sig, int pdfLength) {
        if (sig == null || sig.getByteRange() == null) {
            return false;
        }

        int[] byteRange = sig.getByteRange();

        if (byteRange.length != 4) {
            return false;
        }

        for (int value : byteRange) {
            if (value < 0) {
                return false;
            }
        }

        long start1 = byteRange[0];
        long length1 = byteRange[1];
        long start2 = byteRange[2];
        long length2 = byteRange[3];

        long end1 = start1 + length1;
        long end2 = start2 + length2;

        if (start1 != 0) {
            return false;
        }

        if (length1 <= 0 || length2 <= 0) {
            return false;
        }

        if (start2 <= end1) {
            return false;
        }

        return end2 <= pdfLength;
    }

    private boolean byteRangeCoversWholeFile(PDSignature sig, int pdfLength) {
        if (sig == null || sig.getByteRange() == null) {
            return false;
        }

        int[] byteRange = sig.getByteRange();

        if (byteRange.length != 4) {
            return false;
        }

        long end2 = (long) byteRange[2] + (long) byteRange[3];

        if (end2 == pdfLength) {
            return true;
        }

        return false;
    }

    private PostSignatureUpdateAnalysis analyzePostSignatureUpdate(PDSignature sig, byte[] pdf) {
        PostSignatureUpdateAnalysis analysis = new PostSignatureUpdateAnalysis();
        analysis.detected = false;
        analysis.accepted = false;
        analysis.type = null;
        analysis.bytes = 0L;
        analysis.message = "Sem atualização incremental posterior à revisão assinada.";

        if (sig == null || sig.getByteRange() == null || pdf == null) {
            analysis.detected = true;
            analysis.type = "unknown";
            analysis.message = "Não foi possível analisar a cobertura do ByteRange.";
            return analysis;
        }

        int[] byteRange = sig.getByteRange();
        if (byteRange.length != 4) {
            analysis.detected = true;
            analysis.type = "invalid_byte_range";
            analysis.message = "ByteRange com quantidade inesperada de segmentos.";
            return analysis;
        }

        long signedRevisionEnd = (long) byteRange[2] + (long) byteRange[3];
        long remaining = (long) pdf.length - signedRevisionEnd;

        if (remaining <= 0) {
            analysis.accepted = true;
            analysis.type = "fully_covered";
            analysis.message = "O ByteRange cobre o arquivo PDF final.";
            return analysis;
        }

        analysis.detected = true;
        analysis.bytes = remaining;

        if (remaining > Integer.MAX_VALUE || signedRevisionEnd < 0 || signedRevisionEnd > pdf.length) {
            analysis.type = "unknown";
            analysis.message = "Atualização posterior não analisável pelo tamanho ou posição informada no ByteRange.";
            return analysis;
        }

        int offset = (int) signedRevisionEnd;
        int length = (int) remaining;

        if (isOnlyTrailingPadding(pdf, offset, length)) {
            analysis.accepted = true;
            analysis.type = "trailing_padding";
            analysis.message = "Foram localizados apenas bytes finais sem conteúdo material após a revisão assinada.";
            return analysis;
        }

        String tail = new String(pdf, offset, length, StandardCharsets.ISO_8859_1);
        String compact = tail.replace("\u0000", "");

        boolean hasDss = containsAny(compact, "/DSS", "/VRI", "/OCSPs", "/CRLs", "/Certs");
        boolean hasDocTimeStamp = containsAny(compact, "/DocTimeStamp", "/SubFilter/ETSI.RFC3161", "/SubFilter /ETSI.RFC3161", "ETSI.RFC3161");
        boolean hasAdditionalSignature = containsAny(compact, "/Type/Sig", "/Type /Sig")
                && containsAny(compact, "/ByteRange")
                && containsAny(compact, "/Contents");

        boolean hasXrefKeyword = containsAny(compact, "xref");
        boolean hasTrailerKeyword = containsAny(compact, "trailer");
        boolean hasStartXref = containsAny(compact, "startxref");
        boolean hasEof = containsAny(compact, "%%EOF");
        boolean hasObjectDeclaration = containsPdfObjectDeclaration(compact);
        boolean hasXrefStream = containsAny(compact, "/Type/XRef", "/Type /XRef");
        boolean hasStream = containsAny(compact, "stream", "endstream");

        /*
         * A atualização DSS/LTV costuma conter CRLs, OCSPs e certificados em streams
         * binários. A busca de termos diretamente nesses streams gera falso positivo.
         * Por isso, os riscos de alteração material são pesquisados na estrutura externa,
         * com os corpos dos streams removidos.
         */
        String structureOnly = stripPdfStreamBodies(compact);
        List<PdfObjectSlice> incrementalObjects = parsePdfObjects(compact);

        boolean hasPageContentRisk = containsAny(structureOnly, "/Subtype/Image", "/XObject", "/MediaBox", "/CropBox", "/Rotate");
        boolean hasTextDrawingRisk = containsAny(structureOnly, " BT", " ET", " Tj", " TJ", " Do");
        boolean hasPageTreeRisk = containsAny(structureOnly, "/Page", "/Pages", "/Annots", "/Resources");
        boolean hasActionRisk = containsAny(structureOnly, "/OpenAction", "/AA", "/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/RichMedia");
        boolean hasCatalogOrInfoRisk = containsAny(structureOnly, "/Catalog", "/Root", "/Info", "/Metadata");
        boolean hasMaterialRisk = hasPageContentRisk || hasTextDrawingRisk || hasPageTreeRisk || hasActionRisk;
        boolean dssLtUpgradeNoTsa = isDssLtUpgradeNoTsa(pdf, offset, incrementalObjects, structureOnly, hasDss, hasDocTimeStamp, hasAdditionalSignature);

        boolean hasAnyPdfStructureMarker = hasXrefKeyword
                || hasTrailerKeyword
                || hasStartXref
                || hasEof
                || hasObjectDeclaration
                || hasXrefStream
                || hasStream
                || hasDss
                || hasDocTimeStamp
                || hasAdditionalSignature
                || hasCatalogOrInfoRisk;

        TrailingBytesProfile trailingProfile = profileTrailingBytes(pdf, offset, length);

        String diagnostic = " Diagnóstico da atualização posterior: bytes=" + remaining
                + "; xref=" + hasXrefKeyword
                + "; trailer=" + hasTrailerKeyword
                + "; startxref=" + hasStartXref
                + "; eof=" + hasEof
                + "; obj=" + hasObjectDeclaration
                + "; xrefStream=" + hasXrefStream
                + "; stream=" + hasStream
                + "; dss=" + hasDss
                + "; docTimeStamp=" + hasDocTimeStamp
                + "; assinaturaAdicional=" + hasAdditionalSignature
                + "; riscoConteudo=" + hasMaterialRisk
                + "; dssLtUpgradeNoTsa=" + dssLtUpgradeNoTsa
                + "; bytesNaoBrancos=" + trailingProfile.nonWhitespaceBytes
                + "; bytesImprimiveis=" + trailingProfile.printableBytes
                + "; bytesControleOuBinarios=" + trailingProfile.controlOrBinaryBytes
                + ".";

        boolean xrefTrailerOnly = hasXrefKeyword
                && hasTrailerKeyword
                && hasStartXref
                && hasEof
                && !hasObjectDeclaration
                && !hasMaterialRisk;

        boolean xrefStreamOnly = hasXrefStream
                && hasStartXref
                && hasEof
                && !hasMaterialRisk;

        boolean smallStructuralUpdate = remaining <= 2048
                && hasStartXref
                && hasEof
                && !hasMaterialRisk
                && !hasDss
                && !hasDocTimeStamp
                && !hasAdditionalSignature;

        boolean smallUnreferencedTrailingBytes = remaining <= 2048
                && !hasAnyPdfStructureMarker
                && !hasMaterialRisk
                && trailingProfile.nonWhitespaceBytes > 0
                && trailingProfile.printableBytes == 0;

        if (xrefTrailerOnly) {
            analysis.accepted = true;
            analysis.type = "xref_trailer_only_update";
            analysis.message = "Atualização posterior classificada como atualização estrutural de xref/trailer, sem sinal de alteração de conteúdo." + diagnostic;
            return analysis;
        }

        if (xrefStreamOnly) {
            analysis.accepted = true;
            analysis.type = "xref_stream_only_update";
            analysis.message = "Atualização posterior classificada como atualização estrutural de xref stream, sem sinal de alteração de conteúdo." + diagnostic;
            return analysis;
        }

        if (smallStructuralUpdate) {
            analysis.accepted = true;
            analysis.type = "small_structural_incremental_update";
            analysis.message = "Atualização posterior pequena classificada como atualização estrutural, sem sinal de alteração de conteúdo material." + diagnostic;
            return analysis;
        }

        if (smallUnreferencedTrailingBytes) {
            analysis.accepted = true;
            analysis.type = "small_unreferenced_trailing_bytes";
            analysis.message = "Trecho posterior pequeno classificado como bytes finais não referenciados pela estrutura PDF, sem marcadores de objeto, stream, página, assinatura, DSS/LTV, ação, anexo ou conteúdo textual imprimível." + diagnostic;
            return analysis;
        }

        if (dssLtUpgradeNoTsa) {
            analysis.accepted = true;
            analysis.type = "dss_lt_upgrade_no_tsa";
            analysis.message = "Atualização incremental posterior classificada como inclusão de DSS/VRI, certificados e LCRs, com atualização técnica de catálogo por /DSS e /Extensions ESIC. Não foi localizado DocTimeStamp. Classificação: PAdES-B com DSS embarcado, sem TSA suficiente para classificar como PAdES-LT." + diagnostic;
            return analysis;
        }

        if ((hasDss || hasDocTimeStamp || hasAdditionalSignature) && !hasMaterialRisk) {
            analysis.accepted = true;
            if (hasDocTimeStamp) {
                analysis.type = "document_timestamp_update";
                analysis.message = "Atualização incremental posterior classificada como carimbo do tempo documental ou material técnico correlato." + diagnostic;
            } else if (hasDss) {
                analysis.type = "dss_ltv_update";
                analysis.message = "Atualização incremental posterior classificada como inclusão de dados de validação DSS/LTV. A análise ignorou o conteúdo binário interno dos streams de validação para evitar falso positivo de alteração material." + diagnostic;
            } else {
                analysis.type = "additional_signature_update";
                analysis.message = "Atualização incremental posterior classificada como acréscimo de assinatura digital adicional." + diagnostic;
            }
            return analysis;
        }

        analysis.type = "unknown_incremental_update";
        analysis.message = "Foi detectada atualização incremental posterior à revisão assinada, mas ela não foi classificada como atualização estrutural, DSS/LTV, carimbo do tempo ou assinatura adicional sem sinais de alteração de conteúdo." + diagnostic
                + (hasCatalogOrInfoRisk && !hasMaterialRisk ? " Foram encontrados marcadores de catálogo, raiz, informações ou metadados. A ferramenta não aceita automaticamente esse caso sem análise técnica complementar." : "");
        return analysis;
    }

    private boolean isDssLtUpgradeNoTsa(byte[] pdf, int offset, List<PdfObjectSlice> objects, String structureOnly, boolean hasDss, boolean hasDocTimeStamp, boolean hasAdditionalSignature) {
        if (!hasDss || hasDocTimeStamp || hasAdditionalSignature || objects == null || objects.isEmpty()) {
            return false;
        }

        if (!containsAny(structureOnly, "/DSS") || !containsAny(structureOnly, "/Extensions") || !containsAny(structureOnly, "/ESIC")) {
            return false;
        }

        if (containsAny(structureOnly, "/OpenAction", "/AA", "/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/RichMedia")) {
            return false;
        }

        Set<Integer> validationRefs = collectValidationArtifactObjectNumbers(objects);
        boolean hasCatalogWithDssAndEsic = false;
        boolean hasDssObject = false;
        boolean hasVriObject = false;

        for (PdfObjectSlice object : objects) {
            String body = object.body == null ? "" : object.body;
            String bodyStructure = stripPdfStreamBodies(body);
            String normalized = normalizePdfSyntax(bodyStructure);

            if (validationRefs.contains(object.number)) {
                if (containsAny(bodyStructure, "/Type/DSS", "/Type /DSS")) {
                    hasDssObject = true;
                }
                if (containsAny(bodyStructure, "/Type/VRI", "/Type /VRI")) {
                    hasVriObject = true;
                }
                if (containsAny(bodyStructure, "/OpenAction", "/AA", "/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/RichMedia")) {
                    return false;
                }
                continue;
            }

            if (isCatalogDssEsicObject(bodyStructure)) {
                hasCatalogWithDssAndEsic = true;
                if (containsAny(bodyStructure, "/OpenAction", "/AA", "/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/RichMedia")) {
                    return false;
                }
                continue;
            }

            if (isMetadataObject(bodyStructure) || isInfoDictionaryObject(bodyStructure)) {
                continue;
            }

            if (containsAny(bodyStructure, "/Type/Pages", "/Type /Pages", "/Type/Page", "/Type /Page")) {
                if (isSameAsPreviousObject(pdf, offset, object.number, object.generation, bodyStructure)) {
                    continue;
                }
                return false;
            }

            if (normalized.isBlank()) {
                continue;
            }

            return false;
        }

        return hasCatalogWithDssAndEsic && hasDssObject && hasVriObject;
    }

    private List<PdfObjectSlice> parsePdfObjects(String text) {
        List<PdfObjectSlice> objects = new ArrayList<>();
        if (text == null || text.isBlank()) {
            return objects;
        }

        Pattern pattern = Pattern.compile("(?s)(\\d+)\\s+(\\d+)\\s+obj\\b(.*?)endobj");
        Matcher matcher = pattern.matcher(text);

        while (matcher.find()) {
            PdfObjectSlice object = new PdfObjectSlice();
            object.number = parseIntOrDefault(matcher.group(1), -1);
            object.generation = parseIntOrDefault(matcher.group(2), 0);
            object.body = matcher.group(3) == null ? "" : matcher.group(3);
            objects.add(object);
        }

        return objects;
    }

    private Set<Integer> collectValidationArtifactObjectNumbers(List<PdfObjectSlice> objects) {
        Set<Integer> result = new HashSet<>();
        if (objects == null || objects.isEmpty()) {
            return result;
        }

        boolean changed;
        do {
            changed = false;
            for (PdfObjectSlice object : objects) {
                String body = object.body == null ? "" : object.body;
                boolean seed = containsAny(body, "/Type/DSS", "/Type /DSS", "/Type/VRI", "/Type /VRI", "/Certs", "/CRLs", "/OCSPs", "/VRI");
                if (seed || result.contains(object.number)) {
                    if (result.add(object.number)) {
                        changed = true;
                    }
                    for (Integer ref : collectObjectReferences(body)) {
                        if (result.add(ref)) {
                            changed = true;
                        }
                    }
                }
            }
        } while (changed);

        return result;
    }

    private Set<Integer> collectObjectReferences(String text) {
        Set<Integer> refs = new HashSet<>();
        if (text == null || text.isBlank()) {
            return refs;
        }

        Pattern pattern = Pattern.compile("(\\d+)\\s+\\d+\\s+R\\b");
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            refs.add(parseIntOrDefault(matcher.group(1), -1));
        }
        refs.remove(-1);
        return refs;
    }

    private boolean isCatalogDssEsicObject(String body) {
        if (body == null) {
            return false;
        }
        return containsAny(body, "/Type/Catalog", "/Type /Catalog")
                && containsAny(body, "/DSS")
                && containsAny(body, "/Extensions")
                && containsAny(body, "/ESIC");
    }

    private boolean isMetadataObject(String body) {
        if (body == null) {
            return false;
        }
        return containsAny(body, "/Type/Metadata", "/Type /Metadata", "/Subtype/XML", "/Subtype /XML")
                && !containsAny(body, "/Subtype/Image", "/JavaScript", "/EmbeddedFile", "/RichMedia");
    }

    private boolean isInfoDictionaryObject(String body) {
        if (body == null) {
            return false;
        }
        return containsAny(body, "/Creator", "/Producer", "/CreationDate", "/ModDate", "/Author")
                && !containsAny(body, "/OpenAction", "/AA", "/JavaScript", "/JS", "/EmbeddedFile", "/RichMedia", "/Subtype/Image");
    }

    private boolean isSameAsPreviousObject(byte[] pdf, int offset, int number, int generation, String currentBody) {
        String previous = findPreviousObjectBody(pdf, offset, number, generation);
        if (previous == null) {
            return false;
        }
        return normalizePdfSyntax(previous).equals(normalizePdfSyntax(currentBody));
    }

    private String findPreviousObjectBody(byte[] pdf, int offset, int number, int generation) {
        if (pdf == null || offset <= 0 || offset > pdf.length) {
            return null;
        }

        String prefix = new String(pdf, 0, offset, StandardCharsets.ISO_8859_1);
        Pattern pattern = Pattern.compile("(?s)" + number + "\\s+" + generation + "\\s+obj\\b(.*?)endobj");
        Matcher matcher = pattern.matcher(prefix);

        String last = null;
        while (matcher.find()) {
            last = matcher.group(1);
        }
        return last;
    }

    private String normalizePdfSyntax(String value) {
        if (value == null) {
            return "";
        }
        return stripPdfStreamBodies(value)
                .replaceAll("\\s+", "")
                .trim();
    }

    private int parseIntOrDefault(String value, int fallback) {
        try {
            return Integer.parseInt(value);
        } catch (Exception e) {
            return fallback;
        }
    }

    private String stripPdfStreamBodies(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }

        String lower = text.toLowerCase();
        StringBuilder out = new StringBuilder(text.length());
        int pos = 0;

        while (pos < text.length()) {
            int streamStart = lower.indexOf("stream", pos);
            if (streamStart < 0) {
                out.append(text, pos, text.length());
                break;
            }

            int streamEnd = lower.indexOf("endstream", streamStart + 6);
            if (streamEnd < 0) {
                out.append(text, pos, text.length());
                break;
            }

            out.append(text, pos, streamStart);
            out.append("stream\nendstream");
            pos = streamEnd + "endstream".length();
        }

        return out.toString();
    }

    private TrailingBytesProfile profileTrailingBytes(byte[] pdf, int offset, int length) {
        TrailingBytesProfile profile = new TrailingBytesProfile();

        if (pdf == null || offset < 0 || length < 0 || offset + length > pdf.length) {
            return profile;
        }

        for (int i = offset; i < offset + length; i++) {
            int value = pdf[i] & 0xFF;
            boolean whitespace = value == 0x00 || value == 0x09 || value == 0x0A || value == 0x0C || value == 0x0D || value == 0x20;
            if (!whitespace) {
                profile.nonWhitespaceBytes++;
            }
            if (value >= 0x21 && value <= 0x7E) {
                profile.printableBytes++;
            } else if (!whitespace) {
                profile.controlOrBinaryBytes++;
            }
        }

        return profile;
    }

    private boolean containsPdfObjectDeclaration(String text) {
        if (text == null || text.isBlank()) {
            return false;
        }

        String[] lines = text.split("\\R");
        for (String line : lines) {
            if (line != null && line.trim().matches("^\\d+\\s+\\d+\\s+obj\\b.*")) {
                return true;
            }
        }
        return false;
    }

    private boolean isOnlyTrailingPaddingAfterSignedRevision(PDSignature sig, int pdfLength, byte[] pdf) {
        if (sig == null || sig.getByteRange() == null || pdf == null) {
            return false;
        }

        int[] byteRange = sig.getByteRange();
        if (byteRange.length != 4) {
            return false;
        }

        long signedRevisionEnd = (long) byteRange[2] + (long) byteRange[3];
        long remaining = (long) pdfLength - signedRevisionEnd;

        if (remaining <= 0) {
            return true;
        }

        if (remaining > Integer.MAX_VALUE || signedRevisionEnd < 0 || signedRevisionEnd > pdfLength) {
            return false;
        }

        return isOnlyTrailingPadding(pdf, (int) signedRevisionEnd, (int) remaining);
    }

    private boolean isOnlyTrailingPadding(byte[] pdf, int offset, int length) {
        if (pdf == null || offset < 0 || length < 0 || offset + length > pdf.length) {
            return false;
        }

        for (int i = offset; i < offset + length; i++) {
            byte b = pdf[i];
            if (!(b == 0x00 || b == 0x09 || b == 0x0A || b == 0x0C || b == 0x0D || b == 0x20)) {
                return false;
            }
        }
        return true;
    }

    private boolean containsAny(String text, String... tokens) {
        if (text == null) {
            return false;
        }
        for (String token : tokens) {
            if (token != null && text.contains(token)) {
                return true;
            }
        }
        return false;
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
            CmsCertificateBundle bundle = extractCertificatesFromCms(contents);
            X509Certificate cert = bundle.signerCertificate;

            if (cert == null) {
                info.validatorWarnings.add("Certificado do assinante não localizado no CMS.");
                return;
            }

            info.certificateSubject = cert.getSubjectX500Principal().getName();
            info.certificateIssuer = cert.getIssuerX500Principal().getName();
            info.certificateNotBefore = DATE_FORMAT.format(cert.getNotBefore().toInstant().atZone(ZoneId.systemDefault()));
            info.certificateNotAfter = DATE_FORMAT.format(cert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()));
            info.certificateSerialNumber = formatCertificateSerialNumber(certificate);
info.certificateSerialNumberHex = certificate.getSerialNumber() == null
        ? null
        : certificate.getSerialNumber().toString(16).toUpperCase(java.util.Locale.ROOT);
info.certificateIssuerName = certificate.getIssuerX500Principal().getName();

            if (looksLikeIcpBrasil(cert)) {
                info.icpBrasil = true;
            }
        } catch (Exception e) {
            info.validatorWarnings.add("Não foi possível extrair certificado do CMS: " + e.getMessage());
        }
    }

    private ChainValidationOutcome validateIcpBrasilChain(byte[] contents, Date validationDate) {
        ChainValidationOutcome outcome = new ChainValidationOutcome();

        try {
            CmsCertificateBundle bundle = extractCertificatesFromCms(contents);

            if (bundle.signerCertificate == null) {
                outcome.checked = false;
                outcome.valid = false;
                outcome.message = "Cadeia não verificada: certificado do assinante não localizado no CMS.";
                return outcome;
            }

            List<X509Certificate> trustAnchorsCerts = loadTrustAnchorCertificates();

            if (trustAnchorsCerts.isEmpty()) {
                outcome.checked = false;
                outcome.valid = false;
                outcome.message = "Cadeia não verificada: nenhuma âncora confiável ICP-Brasil cadastrada no projeto.";
                return outcome;
            }

            Set<TrustAnchor> trustAnchors = new HashSet<>();
            for (X509Certificate root : trustAnchorsCerts) {
                trustAnchors.add(new TrustAnchor(root, null));
            }

            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(bundle.signerCertificate);

            PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, selector);
            params.setRevocationEnabled(false);
            params.setDate(validationDate == null ? new Date() : validationDate);

            List<X509Certificate> certsForPath = new ArrayList<>();
            certsForPath.addAll(bundle.certificates);
            certsForPath.addAll(fetchIssuerCertificatesByAia(bundle.signerCertificate, bundle.certificates, 5));
            certsForPath.addAll(trustAnchorsCerts);

            CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certsForPath));
            params.addCertStore(store);

            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(params);

            CertPath certPath = result.getCertPath();

            outcome.checked = true;
            outcome.valid = true;
            outcome.trustAnchor = result.getTrustAnchor().getTrustedCert() == null
                    ? "Âncora ICP-Brasil"
                    : result.getTrustAnchor().getTrustedCert().getSubjectX500Principal().getName();

            for (java.security.cert.Certificate c : certPath.getCertificates()) {
                if (c instanceof X509Certificate x509) {
                    outcome.chainPath.add(x509.getSubjectX500Principal().getName());
                }
            }

            if (result.getTrustAnchor().getTrustedCert() != null) {
                outcome.chainPath.add(result.getTrustAnchor().getTrustedCert().getSubjectX500Principal().getName());
            }

            outcome.message = "Cadeia de certificação validada até âncora confiável da ICP-Brasil.";

            return outcome;
        } catch (Exception e) {
            outcome.checked = true;
            outcome.valid = false;
            outcome.message = "Cadeia não validada: " + e.getClass().getSimpleName() + " - " + safeMessage(e);
            return outcome;
        }
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private CmsCertificateBundle extractCertificatesFromCms(byte[] contents) throws Exception {
        CmsCertificateBundle bundle = new CmsCertificateBundle();

        if (contents == null || contents.length == 0) {
            return bundle;
        }

        CMSSignedData cms = new CMSSignedData(contents);
        SignerInformationStore signers = cms.getSignerInfos();
        Collection<SignerInformation> signerInfos = signers.getSigners();

        Store certStore = cms.getCertificates();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        Collection allMatches = certStore.getMatches(null);
        for (Object holder : allMatches) {
            X509Certificate cert = convertCertificateHolder(holder, factory);
            if (cert != null) {
                bundle.certificates.add(cert);
            }
        }

        for (SignerInformation signer : signerInfos) {
            Collection matches = certStore.getMatches(signer.getSID());

            if (!matches.isEmpty()) {
                Object holder = matches.iterator().next();
                X509Certificate cert = convertCertificateHolder(holder, factory);
                if (cert != null) {
                    bundle.signerCertificate = cert;
                    return bundle;
                }
            }
        }

        return bundle;
    }

    private X509Certificate convertCertificateHolder(Object holder, CertificateFactory factory) {
        try {
            Method getEncoded = holder.getClass().getMethod("getEncoded");
            byte[] certBytes = (byte[]) getEncoded.invoke(holder);
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (Exception e) {
            return null;
        }
    }

    private List<X509Certificate> loadTrustAnchorCertificates() {
        List<X509Certificate> certs = new ArrayList<>();

        certs.addAll(loadTrustAnchorsFromEnvironmentDirectory());
        certs.addAll(loadTrustAnchorsFromResources());

        return certs;
    }

    private List<X509Certificate> loadTrustAnchorsFromEnvironmentDirectory() {
        List<X509Certificate> certs = new ArrayList<>();
        String dirPath = System.getenv("ICP_TRUST_ANCHORS_DIR");

        if (dirPath == null || dirPath.isBlank()) {
            return certs;
        }

        File dir = new File(dirPath);
        if (!dir.exists() || !dir.isDirectory()) {
            return certs;
        }

        File[] files = dir.listFiles((file) -> {
            String n = file.getName().toLowerCase();
            return n.endsWith(".cer") || n.endsWith(".crt") || n.endsWith(".pem");
        });

        if (files == null) {
            return certs;
        }

        for (File file : files) {
            X509Certificate cert = readCertificateFromFile(file);
            if (cert != null && looksLikeIcpBrasilRoot(cert)) {
                certs.add(cert);
            }
        }

        return certs;
    }

    private List<X509Certificate> loadTrustAnchorsFromResources() {
        List<X509Certificate> certs = new ArrayList<>();
        List<String> extensions = List.of("cer", "crt", "pem");

        for (int version = 1; version <= 13; version++) {
            for (String ext : extensions) {
                String resourceName = TRUST_ANCHOR_RESOURCE_DIR + "ac-raiz-icp-brasil-v" + version + "." + ext;
                X509Certificate cert = readCertificateFromResource(resourceName);

                if (cert != null && looksLikeIcpBrasilRoot(cert)) {
                    certs.add(cert);
                }
            }
        }

        return certs;
    }

    private X509Certificate readCertificateFromResource(String resourceName) {
        try (InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourceName)) {
            if (in == null) {
                return null;
            }

            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(in);
        } catch (Exception e) {
            return null;
        }
    }

    private X509Certificate readCertificateFromFile(File file) {
        try (InputStream in = new FileInputStream(file)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(in);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean looksLikeIcpBrasilRoot(X509Certificate cert) {
        if (cert == null) {
            return false;
        }

        String subject = cert.getSubjectX500Principal().getName().toUpperCase();
        String issuer = cert.getIssuerX500Principal().getName().toUpperCase();

        boolean selfIssued = subject.equals(issuer);

        return selfIssued
                && subject.contains("ICP-BRASIL")
                && (subject.contains("AUTORIDADE CERTIFICADORA RAIZ BRASILEIRA")
                    || subject.contains("AC RAIZ")
                    || subject.contains("AC-RAIZ"));
    }



    private RevocationOutcome checkRevocationByOcspThenCrl(byte[] contents) {
        RevocationOutcome ocsp = checkRevocationByOcsp(contents);

        if (ocsp.checked) {
            return ocsp;
        }

        RevocationOutcome crl = checkRevocationByCrl(contents);

        if (crl.checked) {
            crl.message = crl.message + " OCSP não utilizado ou não conclusivo: " + safeText(ocsp.message);
            return crl;
        }

        RevocationOutcome outcome = new RevocationOutcome();
        outcome.checked = false;
        outcome.revoked = false;
        outcome.message = "Revogação não verificada por OCSP nem por LCR. OCSP: " + safeText(ocsp.message) + " LCR: " + safeText(crl.message);
        return outcome;
    }

    private RevocationOutcome checkRevocationByOcsp(byte[] contents) {
        RevocationOutcome outcome = new RevocationOutcome();
        outcome.method = "OCSP";

        try {
            CmsCertificateBundle bundle = extractCertificatesFromCms(contents);

            if (bundle.signerCertificate == null) {
                outcome.checked = false;
                outcome.revoked = false;
                outcome.message = "OCSP não verificado: certificado do assinante não localizado no CMS.";
                return outcome;
            }

            List<X509Certificate> issuerCandidates = new ArrayList<>();
            issuerCandidates.addAll(bundle.certificates);
            issuerCandidates.addAll(fetchIssuerCertificatesByAia(bundle.signerCertificate, bundle.certificates, 5));
            issuerCandidates.addAll(loadTrustAnchorCertificates());

            X509Certificate issuerCertificate = findIssuerCertificate(bundle.signerCertificate, issuerCandidates);

            if (issuerCertificate == null) {
                outcome.checked = false;
                outcome.revoked = false;
                outcome.message = "OCSP não verificado: certificado emissor não localizado no pacote de assinatura nem por AIA.";
                return outcome;
            }

            List<String> ocspUrls = getOcspUrls(bundle.signerCertificate);

            if (ocspUrls.isEmpty()) {
                outcome.checked = false;
                outcome.revoked = false;
                outcome.message = "OCSP não verificado: o certificado não informa endereço OCSP na extensão AIA.";
                return outcome;
            }

            List<String> failures = new ArrayList<>();

            for (String ocspUrl : ocspUrls) {
                try {
                    OcspCheckResult ocsp = queryOcsp(ocspUrl, bundle.signerCertificate, issuerCertificate);

                    outcome.checked = ocsp.checked;
                    outcome.method = "OCSP";
                    outcome.ocspUrl = ocspUrl;
                    outcome.ocspStatus = ocsp.status;
                    outcome.ocspResponder = ocsp.responder;
                    outcome.ocspProducedAt = ocsp.producedAt;
                    outcome.ocspThisUpdate = ocsp.thisUpdate;
                    outcome.ocspNextUpdate = ocsp.nextUpdate;

                    if (!ocsp.checked) {
                        failures.add(ocspUrl + " -> " + safeText(ocsp.message));
                        continue;
                    }

                    if (ocsp.revoked) {
                        outcome.revoked = true;
                        outcome.revocationDate = ocsp.revocationDate;
                        outcome.revocationReason = ocsp.revocationReason;
                        outcome.message = "Consulta de revogação por OCSP realizada. O certificado consta como revogado pelo respondedor OCSP.";
                        return outcome;
                    }

                    if ("good".equalsIgnoreCase(ocsp.status)) {
                        outcome.revoked = false;
                        outcome.message = "Consulta de revogação por OCSP realizada. O respondedor informou status good para o certificado.";
                        return outcome;
                    }

                    failures.add(ocspUrl + " -> status OCSP não conclusivo: " + safeText(ocsp.status));
                } catch (Exception e) {
                    failures.add(ocspUrl + " -> " + e.getClass().getSimpleName() + ": " + safeMessage(e));
                }
            }

            outcome.checked = false;
            outcome.revoked = false;
            outcome.message = "OCSP não verificado: não foi possível obter resposta conclusiva dos endereços OCSP informados. Falhas: " + String.join(" | ", failures);
            return outcome;
        } catch (Exception e) {
            outcome.checked = false;
            outcome.revoked = false;
            outcome.message = "OCSP não verificado: " + e.getClass().getSimpleName() + " - " + safeMessage(e);
            return outcome;
        }
    }

    private OcspCheckResult queryOcsp(String ocspUrl, X509Certificate certificate, X509Certificate issuerCertificate) throws Exception {
        OcspCheckResult result = new OcspCheckResult();
        result.url = ocspUrl;

        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build();

        CertificateID certificateId = new CertificateID(
                digestCalculatorProvider.get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuerCertificate),
                certificate.getSerialNumber()
        );

        OCSPReqBuilder requestBuilder = new OCSPReqBuilder();
        requestBuilder.addRequest(certificateId);
        OCSPReq request = requestBuilder.build();

        OCSPResp response = postOcspRequest(ocspUrl, request);

        if (response.getStatus() != OCSPResp.SUCCESSFUL) {
            result.checked = false;
            result.message = "respondedor OCSP retornou status " + response.getStatus();
            return result;
        }

        Object responseObject = response.getResponseObject();
        if (!(responseObject instanceof BasicOCSPResp basicResponse)) {
            result.checked = false;
            result.message = "resposta OCSP sem BasicOCSPResp";
            return result;
        }

        result.responder = "Resposta OCSP validada";
        result.producedAt = basicResponse.getProducedAt() == null ? null : DATE_FORMAT.format(basicResponse.getProducedAt().toInstant().atZone(ZoneId.systemDefault()));

        if (!isOcspResponseSignatureValid(basicResponse, issuerCertificate)) {
            result.checked = false;
            result.message = "assinatura da resposta OCSP não validada com emissor ou respondedor delegado";
            return result;
        }

        SingleResp[] responses = basicResponse.getResponses();
        if (responses == null || responses.length == 0) {
            result.checked = false;
            result.message = "resposta OCSP sem SingleResp";
            return result;
        }

        SingleResp matched = null;
        for (SingleResp single : responses) {
            if (single != null && certificateId.equals(single.getCertID())) {
                matched = single;
                break;
            }
        }

        if (matched == null) {
            matched = responses[0];
        }

        result.thisUpdate = matched.getThisUpdate() == null ? null : DATE_FORMAT.format(matched.getThisUpdate().toInstant().atZone(ZoneId.systemDefault()));
        result.nextUpdate = matched.getNextUpdate() == null ? null : DATE_FORMAT.format(matched.getNextUpdate().toInstant().atZone(ZoneId.systemDefault()));

        Object status = matched.getCertStatus();

        if (status == CertificateStatus.GOOD || status == null) {
            result.checked = true;
            result.revoked = false;
            result.status = "good";
            result.message = "OCSP good";
            return result;
        }

        if (status instanceof RevokedStatus revokedStatus) {
            result.checked = true;
            result.revoked = true;
            result.status = "revoked";
            result.revocationDate = revokedStatus.getRevocationTime() == null ? null : DATE_FORMAT.format(revokedStatus.getRevocationTime().toInstant().atZone(ZoneId.systemDefault()));
            if (revokedStatus.hasRevocationReason()) {
                result.revocationReason = String.valueOf(revokedStatus.getRevocationReason());
            }
            result.message = "OCSP revoked";
            return result;
        }

        if (status instanceof UnknownStatus) {
            result.checked = false;
            result.revoked = false;
            result.status = "unknown";
            result.message = "OCSP unknown";
            return result;
        }

        result.checked = false;
        result.revoked = false;
        result.status = String.valueOf(status);
        result.message = "status OCSP não reconhecido";
        return result;
    }

    private OCSPResp postOcspRequest(String ocspUrl, OCSPReq request) throws Exception {
        URL url = URI.create(ocspUrl).toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(30000);
        connection.setInstanceFollowRedirects(true);
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/ocsp-request");
        connection.setRequestProperty("Accept", "application/ocsp-response");
        connection.setRequestProperty("User-Agent", "atesta-signature-validator/1.0");

        byte[] encoded = request.getEncoded();
        connection.setRequestProperty("Content-Length", String.valueOf(encoded.length));

        try (OutputStream out = connection.getOutputStream()) {
            out.write(encoded);
        }

        int status = connection.getResponseCode();
        if (status < 200 || status >= 300) {
            throw new IllegalStateException("HTTP " + status + " ao consultar OCSP");
        }

        try (InputStream in = connection.getInputStream()) {
            return new OCSPResp(in.readAllBytes());
        } finally {
            connection.disconnect();
        }
    }

    private boolean isOcspResponseSignatureValid(BasicOCSPResp basicResponse, X509Certificate issuerCertificate) {
        try {
            ContentVerifierProvider issuerVerifier = new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(issuerCertificate.getPublicKey());

            if (basicResponse.isSignatureValid(issuerVerifier)) {
                return true;
            }
        } catch (Exception ignored) {
            // tenta certificados de respondedor delegado abaixo
        }

        try {
            X509CertificateHolder[] holders = basicResponse.getCerts();
            if (holders == null || holders.length == 0) {
                return false;
            }

            JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME);

            for (X509CertificateHolder holder : holders) {
                try {
                    X509Certificate responderCertificate = converter.getCertificate(holder);
                    responderCertificate.checkValidity();

                    boolean issuedByCertificateIssuer = responderCertificate.getIssuerX500Principal().equals(issuerCertificate.getSubjectX500Principal());
                    if (issuedByCertificateIssuer) {
                        responderCertificate.verify(issuerCertificate.getPublicKey());
                    }

                    boolean sameAsIssuer = responderCertificate.equals(issuerCertificate);
                    boolean hasOcspEku = false;
                    try {
                        List<String> eku = responderCertificate.getExtendedKeyUsage();
                        hasOcspEku = eku != null && eku.contains(KeyPurposeId.id_kp_OCSPSigning.getId());
                    } catch (Exception ignored) {
                        hasOcspEku = false;
                    }

                    if (!sameAsIssuer && !(issuedByCertificateIssuer && hasOcspEku)) {
                        continue;
                    }

                    ContentVerifierProvider responderVerifier = new JcaContentVerifierProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(responderCertificate.getPublicKey());

                    if (basicResponse.isSignatureValid(responderVerifier)) {
                        return true;
                    }
                } catch (Exception ignored) {
                    // tenta o próximo certificado contido na resposta OCSP
                }
            }
        } catch (Exception ignored) {
            return false;
        }

        return false;
    }

    private List<String> getOcspUrls(X509Certificate certificate) {
        LinkedHashSet<String> urls = new LinkedHashSet<>();

        try {
            byte[] extensionValue = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());

            if (extensionValue == null) {
                return new ArrayList<>();
            }

            ASN1OctetString octets = ASN1OctetString.getInstance(extensionValue);
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(octets.getOctets());

            for (AccessDescription description : aia.getAccessDescriptions()) {
                if (!"1.3.6.1.5.5.7.48.1".equals(description.getAccessMethod().getId())) {
                    continue;
                }

                GeneralName accessLocation = description.getAccessLocation();
                if (accessLocation != null && accessLocation.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    String url = DERIA5String.getInstance(accessLocation.getName()).getString();
                    if (url != null && !url.isBlank() && (url.startsWith("http://") || url.startsWith("https://"))) {
                        urls.add(url);
                    }
                }
            }
        } catch (Exception ignored) {
            // Sem URL OCSP legível.
        }

        return new ArrayList<>(urls);
    }

    private RevocationOutcome checkRevocationByCrl(byte[] contents) {
        RevocationOutcome outcome = new RevocationOutcome();

        try {
            CmsCertificateBundle bundle = extractCertificatesFromCms(contents);

            if (bundle.signerCertificate == null) {
                outcome.checked = false;
                outcome.revoked = false;
                outcome.message = "Revogação não verificada: certificado do assinante não localizado no CMS.";
                return outcome;
            }

            List<X509Certificate> issuerCandidates = new ArrayList<>();
            issuerCandidates.addAll(bundle.certificates);
            issuerCandidates.addAll(fetchIssuerCertificatesByAia(bundle.signerCertificate, bundle.certificates, 5));
            issuerCandidates.addAll(loadTrustAnchorCertificates());

            X509Certificate issuerCertificate = findIssuerCertificate(bundle.signerCertificate, issuerCandidates);

            if (issuerCertificate == null) {
                outcome.checked = false;
                outcome.revoked = false;
                outcome.message = "Revogação não verificada: certificado emissor não localizado no pacote de assinatura nem por AIA.";
                return outcome;
            }

            List<String> crlUrls = getCrlDistributionPointUrls(bundle.signerCertificate);

            if (crlUrls.isEmpty()) {
                outcome.checked = false;
                outcome.revoked = false;
                outcome.message = "Revogação não verificada: o certificado não informa ponto de distribuição de LCR.";
                return outcome;
            }

            List<String> failures = new ArrayList<>();

            for (String crlUrl : crlUrls) {
                try {
                    X509CRL crl = downloadCrl(crlUrl);
                    validateCrlIssuer(crl, issuerCertificate);

                    outcome.checked = true;
                    outcome.method = "CRL";
                    outcome.crlUrl = crlUrl;
                    outcome.crlIssuer = crl.getIssuerX500Principal().getName();
                    outcome.thisUpdate = crl.getThisUpdate() == null ? null : DATE_FORMAT.format(crl.getThisUpdate().toInstant().atZone(ZoneId.systemDefault()));
                    outcome.nextUpdate = crl.getNextUpdate() == null ? null : DATE_FORMAT.format(crl.getNextUpdate().toInstant().atZone(ZoneId.systemDefault()));

                    X509CRLEntry revokedEntry = crl.getRevokedCertificate(bundle.signerCertificate.getSerialNumber());

                    if (revokedEntry != null) {
                        outcome.revoked = true;
                        outcome.revocationDate = revokedEntry.getRevocationDate() == null ? null : DATE_FORMAT.format(revokedEntry.getRevocationDate().toInstant().atZone(ZoneId.systemDefault()));
                        outcome.revocationReason = revokedEntry.getRevocationReason() == null ? null : revokedEntry.getRevocationReason().name();
                        outcome.message = "Certificado consta como revogado na LCR consultada.";
                        return outcome;
                    }

                    outcome.revoked = false;
                    outcome.message = "Consulta de revogação por LCR realizada. O certificado não consta como revogado na LCR consultada.";
                    return outcome;
                } catch (Exception e) {
                    failures.add(crlUrl + " -> " + e.getClass().getSimpleName() + ": " + safeMessage(e));
                }
            }

            outcome.checked = false;
            outcome.revoked = false;
            outcome.message = "Revogação não verificada: não foi possível consultar ou validar as LCRs informadas no certificado. Falhas: " + String.join(" | ", failures);
            return outcome;
        } catch (Exception e) {
            outcome.checked = false;
            outcome.revoked = false;
            outcome.message = "Revogação não verificada: " + e.getClass().getSimpleName() + " - " + safeMessage(e);
            return outcome;
        }
    }

    private X509Certificate findIssuerCertificate(X509Certificate certificate, List<X509Certificate> candidates) {
        if (certificate == null || candidates == null) {
            return null;
        }

        for (X509Certificate candidate : candidates) {
            if (candidate == null) {
                continue;
            }

            try {
                if (certificate.getIssuerX500Principal().equals(candidate.getSubjectX500Principal())) {
                    certificate.verify(candidate.getPublicKey());
                    return candidate;
                }
            } catch (Exception ignored) {
                // candidato não assina o certificado analisado
            }
        }

        return null;
    }

    private List<X509Certificate> fetchIssuerCertificatesByAia(X509Certificate certificate, List<X509Certificate> alreadyKnown, int maxDepth) {
        List<X509Certificate> fetched = new ArrayList<>();

        if (certificate == null || maxDepth <= 0) {
            return fetched;
        }

        List<X509Certificate> known = new ArrayList<>();
        if (alreadyKnown != null) {
            known.addAll(alreadyKnown);
        }

        X509Certificate current = certificate;

        for (int depth = 0; depth < maxDepth; depth++) {
            X509Certificate knownIssuer = findIssuerCertificate(current, known);
            if (knownIssuer != null) {
                current = knownIssuer;
                continue;
            }

            List<String> issuerUrls = getCaIssuerUrls(current);
            if (issuerUrls.isEmpty()) {
                break;
            }

            boolean foundAtThisDepth = false;
            for (String issuerUrl : issuerUrls) {
                try {
                    List<X509Certificate> downloaded = downloadCertificates(issuerUrl);
                    for (X509Certificate downloadedCert : downloaded) {
                        if (downloadedCert == null) {
                            continue;
                        }

                        if (!containsCertificate(known, downloadedCert)) {
                            known.add(downloadedCert);
                        }

                        if (!containsCertificate(fetched, downloadedCert)) {
                            fetched.add(downloadedCert);
                        }

                        try {
                            if (current.getIssuerX500Principal().equals(downloadedCert.getSubjectX500Principal())) {
                                current.verify(downloadedCert.getPublicKey());
                                current = downloadedCert;
                                foundAtThisDepth = true;
                            }
                        } catch (Exception ignored) {
                            // Certificado baixado não é emissor direto do certificado atual.
                        }
                    }
                } catch (Exception ignored) {
                    // AIA indisponível ou certificado em formato não suportado nesta URL.
                }
            }

            if (!foundAtThisDepth) {
                break;
            }
        }

        return fetched;
    }

    private boolean containsCertificate(List<X509Certificate> certs, X509Certificate candidate) {
        if (certs == null || candidate == null) {
            return false;
        }

        for (X509Certificate cert : certs) {
            if (cert != null && cert.equals(candidate)) {
                return true;
            }
        }

        return false;
    }

    private List<String> getCaIssuerUrls(X509Certificate certificate) {
        LinkedHashSet<String> urls = new LinkedHashSet<>();

        try {
            byte[] extensionValue = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());

            if (extensionValue == null) {
                return new ArrayList<>();
            }

            ASN1OctetString octets = ASN1OctetString.getInstance(extensionValue);
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(octets.getOctets());

            for (AccessDescription description : aia.getAccessDescriptions()) {
                if (!"1.3.6.1.5.5.7.48.2".equals(description.getAccessMethod().getId())) {
                    continue;
                }

                GeneralName accessLocation = description.getAccessLocation();
                if (accessLocation != null && accessLocation.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    String url = DERIA5String.getInstance(accessLocation.getName()).getString();
                    if (url != null && !url.isBlank() && (url.startsWith("http://") || url.startsWith("https://"))) {
                        urls.add(url);
                    }
                }
            }
        } catch (Exception ignored) {
            // Sem URL legível de certificado emissor.
        }

        return new ArrayList<>(urls);
    }

    private List<X509Certificate> downloadCertificates(String certificateUrl) throws Exception {
        URL url = URI.create(certificateUrl).toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(30000);
        connection.setInstanceFollowRedirects(true);
        connection.setRequestProperty("User-Agent", "atesta-signature-validator/1.0");

        int status = connection.getResponseCode();
        if (status < 200 || status >= 300) {
            throw new IllegalStateException("HTTP " + status + " ao baixar certificado emissor");
        }

        try (InputStream in = connection.getInputStream()) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Collection<? extends java.security.cert.Certificate> downloaded = factory.generateCertificates(in);
            List<X509Certificate> certs = new ArrayList<>();

            for (java.security.cert.Certificate cert : downloaded) {
                if (cert instanceof X509Certificate x509) {
                    certs.add(x509);
                }
            }

            return certs;
        } finally {
            connection.disconnect();
        }
    }

    private List<String> getCrlDistributionPointUrls(X509Certificate certificate) {
        LinkedHashSet<String> urls = new LinkedHashSet<>();

        try {
            byte[] extensionValue = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());

            if (extensionValue == null) {
                return new ArrayList<>();
            }

            ASN1OctetString octets = ASN1OctetString.getInstance(extensionValue);
            CRLDistPoint distPoint = CRLDistPoint.getInstance(octets.getOctets());

            for (DistributionPoint point : distPoint.getDistributionPoints()) {
                DistributionPointName name = point.getDistributionPoint();

                if (name == null || name.getType() != DistributionPointName.FULL_NAME) {
                    continue;
                }

                GeneralNames generalNames = GeneralNames.getInstance(name.getName());

                for (GeneralName generalName : generalNames.getNames()) {
                    if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = DERIA5String.getInstance(generalName.getName()).getString();
                        if (url != null && !url.isBlank() && (url.startsWith("http://") || url.startsWith("https://"))) {
                            urls.add(url);
                        }
                    }
                }
            }
        } catch (Exception ignored) {
            // Sem URL legível de LCR.
        }

        return new ArrayList<>(urls);
    }

    private X509CRL downloadCrl(String crlUrl) throws Exception {
        URL url = URI.create(crlUrl).toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(30000);
        connection.setInstanceFollowRedirects(true);
        connection.setRequestProperty("User-Agent", "atesta-signature-validator/1.0");

        int status = connection.getResponseCode();
        if (status < 200 || status >= 300) {
            throw new IllegalStateException("HTTP " + status + " ao baixar LCR");
        }

        try (InputStream in = connection.getInputStream()) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509CRL) factory.generateCRL(in);
        } finally {
            connection.disconnect();
        }
    }

    private void validateCrlIssuer(X509CRL crl, X509Certificate issuerCertificate) throws Exception {
        if (crl == null) {
            throw new IllegalArgumentException("LCR não carregada.");
        }

        if (issuerCertificate == null) {
            throw new IllegalArgumentException("Certificado emissor não disponível.");
        }

        if (!crl.getIssuerX500Principal().equals(issuerCertificate.getSubjectX500Principal())) {
            throw new IllegalStateException("Emissor da LCR não corresponde ao emissor do certificado analisado.");
        }

        crl.verify(issuerCertificate.getPublicKey());

        Date now = new Date();
        if (crl.getNextUpdate() != null && crl.getNextUpdate().before(now)) {
            throw new IllegalStateException("LCR expirada. Próxima atualização informada: " + DATE_FORMAT.format(crl.getNextUpdate().toInstant().atZone(ZoneId.systemDefault())));
        }
    }

    private boolean looksLikeIcpBrasil(X509Certificate cert) {
        if (cert == null) {
            return false;
        }

        String subject = cert.getSubjectX500Principal().getName().toUpperCase();
        String issuer = cert.getIssuerX500Principal().getName().toUpperCase();

        return subject.contains("ICP-BRASIL")
                || issuer.contains("ICP-BRASIL")
                || subject.contains("ICP BRASIL")
                || issuer.contains("ICP BRASIL");
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
            outcome.message = "Validação técnica PAdES executada.";

            if (result instanceof List list) {
                for (Object signatureInformation : list) {
                    readDemoiselleSignatureInformation(signatureInformation, info);
                }
            }

            if (Boolean.FALSE.equals(info.demoiselleValid) || !info.validatorErrors.isEmpty()) {
                outcome.valid = false;
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



    private PolicyValidationOutcome inspectSignaturePolicy(byte[] contents, SignatureInfo info) {
        PolicyValidationOutcome outcome = new PolicyValidationOutcome();
        outcome.declared = false;
        outcome.recognized = false;
        outcome.message = "Política de assinatura ICP-Brasil tipificada não declarada no pacote assinado.";

        try {
            if (contents == null || contents.length == 0) {
                return outcome;
            }

            CMSSignedData cms = new CMSSignedData(contents);
            SignerInformationStore signerStore = cms.getSignerInfos();
            Collection<SignerInformation> signerInfos = signerStore.getSigners();

            for (SignerInformation signer : signerInfos) {
                AttributeTable signedAttributes = signer.getSignedAttributes();
                if (signedAttributes == null) {
                    continue;
                }

                Attribute policyAttribute = signedAttributes.get(ID_AA_ETS_SIG_POLICY_ID);
                if (policyAttribute == null || policyAttribute.getAttrValues() == null || policyAttribute.getAttrValues().size() == 0) {
                    continue;
                }

                outcome.declared = true;

                ASN1Encodable value = policyAttribute.getAttrValues().getObjectAt(0);
                String oid = extractSignaturePolicyOid(value);

                if (oid == null || oid.isBlank()) {
                    outcome.oid = null;
                    outcome.name = "Política de assinatura declarada, mas o OID não foi extraído";
                    outcome.recognized = false;
                    outcome.message = "Política de assinatura declarada no pacote assinado, mas o OID não foi extraído automaticamente.";
                    return outcome;
                }

                outcome.oid = oid;

                if ("implied".equals(oid)) {
                    outcome.name = "Política de assinatura implícita";
                    outcome.recognized = false;
                    outcome.message = "Política de assinatura implícita detectada. Política de assinatura ICP-Brasil tipificada não declarada no pacote assinado.";
                    return outcome;
                }

                outcome.name = mapSignaturePolicyName(oid);
                outcome.recognized = isIcpBrasilPolicyOid(oid);

                if (outcome.recognized && isIcpBrasilPadesPdfPolicy(oid)) {
                    outcome.message = "Política de assinatura ICP-Brasil para PDF/PAdES declarada no pacote assinado: " + outcome.name + " (OID " + oid + ").";
                } else if (outcome.recognized) {
                    outcome.message = "Política de assinatura ICP-Brasil declarada no pacote assinado: " + outcome.name + " (OID " + oid + "). O OID não pertence ao conjunto específico de políticas PDF/PAdES do arco 2.16.76.1.7.1.11 a 2.16.76.1.7.1.14.";
                } else {
                    outcome.message = "Política de assinatura declarada no pacote assinado, fora do arco ICP-Brasil conhecido: OID " + oid + ".";
                }

                return outcome;
            }

            return outcome;
        } catch (Exception e) {
            outcome.declared = false;
            outcome.recognized = false;
            outcome.message = "Não foi possível verificar a política de assinatura: " + e.getClass().getSimpleName() + " - " + safeMessage(e);
            if (info != null) {
                info.validatorWarnings.add(outcome.message);
            }
            return outcome;
        }
    }

    private String extractSignaturePolicyOid(ASN1Encodable value) {
        if (value == null) {
            return null;
        }

        try {
            SignaturePolicyIdentifier identifier = SignaturePolicyIdentifier.getInstance(value);
            if (identifier == null || identifier.isSignaturePolicyImplied()) {
                return "implied";
            }
            if (identifier.getSignaturePolicyId() != null && identifier.getSignaturePolicyId().getSigPolicyId() != null) {
                return identifier.getSignaturePolicyId().getSigPolicyId().getId();
            }
        } catch (Exception ignored) {
            // fallback textual abaixo
        }

        String text = String.valueOf(value);
        Matcher matcher = Pattern.compile("2\\.16\\.76\\.1\\.7\\.1\\.[0-9]+(?:\\.[0-9]+)*").matcher(text);
        if (matcher.find()) {
            return matcher.group();
        }

        matcher = Pattern.compile("[0-9]+(?:\\.[0-9]+){4,}").matcher(text);
        if (matcher.find()) {
            return matcher.group();
        }

        return null;
    }

    private boolean isIcpBrasilPolicyOid(String oid) {
        return oid != null && oid.startsWith("2.16.76.1.7.1.");
    }

    private boolean isIcpBrasilPadesPdfPolicy(String oid) {
        String family = getIcpBrasilPolicyFamily(oid);
        return "11".equals(family) || "12".equals(family) || "13".equals(family) || "14".equals(family);
    }

    private String getIcpBrasilPolicyFamily(String oid) {
        if (!isIcpBrasilPolicyOid(oid)) {
            return null;
        }

        String suffix = oid.substring("2.16.76.1.7.1.".length());
        if (suffix.isBlank()) {
            return null;
        }

        return suffix.split("\\.")[0];
    }

    private String getPolicyVersionText(String oid) {
        if (!isIcpBrasilPolicyOid(oid)) {
            return "";
        }

        String suffix = oid.substring("2.16.76.1.7.1.".length());
        String[] parts = suffix.split("\\.");

        if (parts.length == 1) {
            return "";
        }

        if (parts.length == 2) {
            return ", versão " + parts[1];
        }

        if (parts.length >= 3) {
            return ", versão " + parts[1] + "." + parts[2];
        }

        return "";
    }

    private String mapSignaturePolicyName(String oid) {
        if (oid == null || oid.isBlank()) {
            return null;
        }

        if ("implied".equals(oid)) {
            return "Política de assinatura implícita";
        }

        if (!isIcpBrasilPolicyOid(oid)) {
            return "Política de assinatura declarada fora do arco ICP-Brasil conhecido";
        }

        String family = getIcpBrasilPolicyFamily(oid);
        String version = getPolicyVersionText(oid);

        switch (family) {
            case "1":
                return "Política ICP-Brasil AD-RB para CMS/CAdES" + version;
            case "2":
                return "Política ICP-Brasil AD-RT para CMS/CAdES" + version;
            case "3":
                return "Política ICP-Brasil AD-RV para CMS/CAdES" + version;
            case "4":
                return "Política ICP-Brasil AD-RC para CMS/CAdES" + version;
            case "5":
                return "Política ICP-Brasil AD-RA para CMS/CAdES" + version;
            case "6":
                return "Política ICP-Brasil AD-RB para XMLDSIG" + version;
            case "7":
                return "Política ICP-Brasil AD-RT para XMLDSIG" + version;
            case "8":
                return "Política ICP-Brasil AD-RV para XMLDSIG" + version;
            case "9":
                return "Política ICP-Brasil AD-RC para XMLDSIG" + version;
            case "10":
                return "Política ICP-Brasil AD-RA para XMLDSIG" + version;
            case "11":
                return "Política ICP-Brasil AD-RB para PDF/PAdES" + version;
            case "12":
                return "Política ICP-Brasil AD-RT para PDF/PAdES" + version;
            case "13":
                return "Política ICP-Brasil AD-RC para PDF/PAdES" + version;
            case "14":
                return "Política ICP-Brasil AD-RA para PDF/PAdES" + version;
            default:
                return "Política de assinatura ICP-Brasil declarada" + version;
        }
    }

    private TimestampValidationOutcome inspectSignatureTimestamp(byte[] contents, SignatureInfo info) {
        TimestampValidationOutcome outcome = new TimestampValidationOutcome();
        outcome.present = false;
        outcome.valid = false;
        outcome.message = "Carimbo do tempo de assinatura não localizado.";

        try {
            if (contents == null || contents.length == 0) {
                return outcome;
            }

            CMSSignedData cms = new CMSSignedData(contents);
            SignerInformationStore signerStore = cms.getSignerInfos();
            Collection<SignerInformation> signerInfos = signerStore.getSigners();

            for (SignerInformation signer : signerInfos) {
                AttributeTable unsignedAttributes = signer.getUnsignedAttributes();
                if (unsignedAttributes == null) {
                    continue;
                }

                Attribute timestampAttribute = unsignedAttributes.get(ID_AA_SIGNATURE_TIMESTAMP_TOKEN);
                if (timestampAttribute == null || timestampAttribute.getAttrValues() == null || timestampAttribute.getAttrValues().size() == 0) {
                    continue;
                }

                outcome.present = true;

                ASN1Encodable value = timestampAttribute.getAttrValues().getObjectAt(0);
                CMSSignedData timestampCms = new CMSSignedData(value.toASN1Primitive().getEncoded());
                TimeStampToken token = new TimeStampToken(timestampCms);
                TimeStampTokenInfo tokenInfo = token.getTimeStampInfo();

                outcome.time = tokenInfo.getGenTime() == null ? null : DATE_FORMAT.format(tokenInfo.getGenTime().toInstant().atZone(ZoneId.systemDefault()));

                String digestAlgorithm = digestNameFromOid(tokenInfo.getMessageImprintAlgOID().getId());
                MessageDigest digest = MessageDigest.getInstance(digestAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
                byte[] calculated = digest.digest(signer.getSignature());
                byte[] declared = tokenInfo.getMessageImprintDigest();

                if (!Arrays.equals(calculated, declared)) {
                    outcome.valid = false;
                    outcome.message = "Carimbo do tempo localizado, mas o hash carimbado não corresponde à assinatura.";
                    return outcome;
                }

                @SuppressWarnings("unchecked")
                Store<X509CertificateHolder> timestampCertificates = token.getCertificates();
                @SuppressWarnings("unchecked")
                Collection<X509CertificateHolder> matches = timestampCertificates.getMatches(token.getSID());
                if (matches == null || matches.isEmpty()) {
                    outcome.valid = false;
                    outcome.message = "Carimbo do tempo localizado, mas o certificado da autoridade de carimbo não foi encontrado no token.";
                    return outcome;
                }

                X509CertificateHolder holder = matches.iterator().next();
                X509Certificate tsaCertificate = new JcaX509CertificateConverter()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .getCertificate(holder);

                token.validate(new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(holder));

                outcome.authority = tsaCertificate.getSubjectX500Principal().getName();
                outcome.valid = true;
                outcome.message = "Carimbo do tempo de assinatura validado. Autoridade de carimbo: " + outcome.authority
                        + (outcome.time == null ? "." : ". Data e hora do carimbo: " + outcome.time + ".");
                return outcome;
            }

            return outcome;
        } catch (Exception e) {
            outcome.present = true;
            outcome.valid = false;
            outcome.message = "Carimbo do tempo localizado, mas não validado: " + e.getClass().getSimpleName() + " - " + safeMessage(e instanceof Exception ? (Exception) e : new Exception(e));
            if (info != null) {
                info.validatorWarnings.add(outcome.message);
            }
            return outcome;
        }
    }

    private String digestNameFromOid(String oid) {
        if ("1.3.14.3.2.26".equals(oid)) return "SHA-1";
        if ("2.16.840.1.101.3.4.2.1".equals(oid)) return "SHA-256";
        if ("2.16.840.1.101.3.4.2.2".equals(oid)) return "SHA-384";
        if ("2.16.840.1.101.3.4.2.3".equals(oid)) return "SHA-512";
        if ("2.16.840.1.101.3.4.2.4".equals(oid)) return "SHA-224";
        return oid;
    }

    private void readDemoiselleSignatureInformation(Object signatureInformation, SignatureInfo info) {
        if (signatureInformation == null) {
            return;
        }

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
                    if (item != null) {
                        destination.add(String.valueOf(item));
                    }
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

    private String safeText(String value) {
        return value == null || value.isBlank() ? "não informada" : value;
    }

    private String safeMessage(Exception e) {
        Throwable t = e.getCause() != null ? e.getCause() : e;
        return t.getMessage() == null ? t.toString() : t.getMessage();
    }

    private static class PdfObjectSlice {
        int number;
        int generation;
        String body;
    }

    private static class PostSignatureUpdateAnalysis {
        boolean detected;
        boolean accepted;
        String type;
        Long bytes;
        String message;
    }

    private static class TrailingBytesProfile {
        int nonWhitespaceBytes;
        int printableBytes;
        int controlOrBinaryBytes;
    }

    private static class PolicyValidationOutcome {
        boolean declared;
        boolean recognized;
        String oid;
        String name;
        String message;
    }

    private static class TimestampValidationOutcome {
        boolean present;
        boolean valid;
        String authority;
        String time;
        String message;
    }

    private static class DemoiselleOutcome {
        boolean checked;
        Boolean valid;
        Boolean icpBrasil;
        String message;
    }

    private static class CmsCertificateBundle {
        X509Certificate signerCertificate;
        List<X509Certificate> certificates = new ArrayList<>();
    }


    private static class OcspCheckResult {
        boolean checked;
        boolean revoked;
        String url;
        String status;
        String responder;
        String producedAt;
        String thisUpdate;
        String nextUpdate;
        String revocationDate;
        String revocationReason;
        String message;
    }

    private static class RevocationOutcome {
        boolean checked;
        boolean revoked;
        String method;
        String ocspUrl;
        String ocspStatus;
        String ocspResponder;
        String ocspProducedAt;
        String ocspThisUpdate;
        String ocspNextUpdate;
        String crlUrl;
        String crlIssuer;
        String thisUpdate;
        String nextUpdate;
        String revocationDate;
        String revocationReason;
        String message;
    }

    private static class ChainValidationOutcome {
        boolean checked;
        boolean valid;
        String trustAnchor;
        String message;
        List<String> chainPath = new ArrayList<>();
    }
}
