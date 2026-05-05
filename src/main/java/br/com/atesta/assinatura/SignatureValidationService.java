package br.com.atesta.assinatura;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
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
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
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

                    RevocationOutcome revocation = checkRevocationByCrl(contents);

                    if (revocation.checked) {
                        anyRevocationChecked = true;
                        out.revocationChecked = true;
                        out.revocationMethod = "CRL";

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
                out.standard = anyPades ? "PAdES-B" : "Assinatura PDF";

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
                            ? "Assinatura PAdES-B validada. Certificado ICP-Brasil identificado. Cadeia de certificação validada até âncora confiável da ICP-Brasil. Consulta de revogação por LCR realizada sem identificação de revogação."
                            : "Assinatura PAdES-B validada sobre a revisão assinada. Certificado ICP-Brasil identificado. Cadeia validada até âncora confiável da ICP-Brasil. Consulta de revogação por LCR realizada sem identificação de revogação. A atualização incremental posterior foi classificada como técnica permitida.";
                    if (!finalDocumentCovered && anyPostSignatureUpdateAccepted) {
                        out.warnings.add("O PDF final contém atualização incremental posterior à assinatura. A atualização foi classificada como técnica permitida: " + safeText(out.postSignatureUpdateType) + ".");
                    }
                    out.warnings.add("OCSP, TSA e política de assinatura ainda serão tratados nas próximas etapas.");
                } else if (anyValid && anyIcp && anyChainValid) {
                    out.result = "valid_icp_brasil_chain_revocation_not_checked";
                    out.valid = null;
                    out.icpBrasil = true;
                    out.revocationChecked = false;
                    out.message = "Assinatura PAdES-B validada e cadeia ICP-Brasil reconhecida, mas a consulta de revogação por LCR não foi concluída.";
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
                    out.warnings.add("Cadeia integral, revogação por LCR ou OCSP, TSA e política de assinatura ainda não foram concluídas.");
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

        out.timestampPresent = false;
        out.timestampValid = null;
        out.timestampAuthority = null;
        out.timestampTime = null;

        out.policyOid = null;
        out.policyName = null;
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

        return isOnlyTrailingPaddingAfterSignedRevision(sig, pdfLength, null);
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

        boolean hasXrefTrailerOnly = containsAny(compact, "xref")
                && containsAny(compact, "trailer")
                && containsAny(compact, "startxref")
                && containsAny(compact, "%%EOF")
                && !containsPdfObjectDeclaration(compact);

        boolean hasXrefStreamOnly = containsAny(compact, "/Type/XRef", "/Type /XRef")
                && containsAny(compact, "startxref")
                && containsAny(compact, "%%EOF")
                && !containsAny(compact, "/Page", "/Pages", "/Contents", "/XObject", "/Font", "/Annots", "/AcroForm");

        boolean hasPageContentRisk = containsAny(compact, "/Subtype/Image", "/XObject", "/Font", "/MediaBox", "/CropBox", "/Rotate");
        boolean hasTextDrawingRisk = containsAny(compact, " BT", " ET", " Tj", " TJ", " Do");
        boolean hasPageTreeRisk = containsAny(compact, "/Page", "/Pages", "/Annots", "/AcroForm", "/Resources");

        if (hasXrefTrailerOnly) {
            analysis.accepted = true;
            analysis.type = "xref_trailer_only_update";
            analysis.message = "Atualização posterior classificada como atualização estrutural de xref/trailer, sem objeto PDF novo e sem indício de alteração de conteúdo.";
            return analysis;
        }

        if (hasXrefStreamOnly) {
            analysis.accepted = true;
            analysis.type = "xref_stream_only_update";
            analysis.message = "Atualização posterior classificada como atualização estrutural de xref stream, sem indício de alteração de conteúdo.";
            return analysis;
        }

        if ((hasDss || hasDocTimeStamp || hasAdditionalSignature) && !hasPageContentRisk && !hasTextDrawingRisk && !hasPageTreeRisk) {
            analysis.accepted = true;
            if (hasDocTimeStamp) {
                analysis.type = "document_timestamp_update";
                analysis.message = "Atualização incremental posterior classificada como carimbo do tempo documental ou material técnico correlato.";
            } else if (hasDss) {
                analysis.type = "dss_ltv_update";
                analysis.message = "Atualização incremental posterior classificada como inclusão de dados de validação DSS/LTV.";
            } else {
                analysis.type = "additional_signature_update";
                analysis.message = "Atualização incremental posterior classificada como acréscimo de assinatura digital adicional.";
            }
            return analysis;
        }

        analysis.type = "unknown_incremental_update";
        analysis.message = "Foi detectada atualização incremental posterior à revisão assinada, mas ela não foi classificada como atualização estrutural, DSS/LTV, carimbo do tempo ou assinatura adicional sem indícios de alteração de conteúdo.";
        return analysis;
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

    private static class PostSignatureUpdateAnalysis {
        boolean detected;
        boolean accepted;
        String type;
        Long bytes;
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

    private static class RevocationOutcome {
        boolean checked;
        boolean revoked;
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
