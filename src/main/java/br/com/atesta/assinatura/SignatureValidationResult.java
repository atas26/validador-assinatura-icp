package br.com.atesta.assinatura;

import java.util.ArrayList;
import java.util.List;

public class SignatureValidationResult {
    public boolean ok;
    public String result;

    public boolean hasSignature;
    public Boolean valid;
    public Boolean icpBrasil;

    // Assinatura gov.br/e-gov
    public Boolean govBr;
    public Boolean govBrAdvanced;
    public Boolean govBrIssuerDetected;
    public String govBrIssuerMatchedBy;
    public String govBrValidationStatus;
    public String govBrMessage;

    public String standard;
    public String validationLevel;
    public String message;

    public List<String> warnings = new ArrayList<>();
    public List<String> errors = new ArrayList<>();
    public List<SignatureInfo> signatures = new ArrayList<>();

    // Contadores de assinaturas
    public int signatureCount;
    public int validSignatureCount;
    public int invalidSignatureCount;
    public int indeterminateSignatureCount;
    public int govBrSignatureCount;
    public int govBrValidSignatureCount;
    public int govBrInvalidSignatureCount;
    public int govBrIndeterminateSignatureCount;
    public int icpBrasilSignatureCount;

    // Integridade da assinatura
    public Boolean signatureIntegrityValid;
    public Boolean byteRangeValid;
    public Boolean finalDocumentCovered;
    public Boolean finalDocumentAcceptable;

    // Atualização incremental posterior à assinatura
    public Boolean postSignatureUpdateDetected;
    public Boolean postSignatureUpdateAccepted;
    public String postSignatureUpdateType;
    public Long postSignatureUpdateBytes;
    public String postSignatureUpdateMessage;

    // Cadeia de certificação
    public Boolean chainValid;
    public String trustAnchor;
    public List<String> chainPath = new ArrayList<>();

    // Revogação
    public Boolean revocationChecked;
    public String revocationMethod;
    public Boolean revoked;
    public String crlUrl;
    public String crlIssuer;
    public String crlThisUpdate;
    public String crlNextUpdate;
    public String revocationDate;
    public String revocationReason;
    public String ocspUrl;
    public String ocspStatus;
    public String ocspResponder;
    public String ocspProducedAt;
    public String ocspThisUpdate;
    public String ocspNextUpdate;

    // Revogação reforçada
    public String revocationStatus;
    public String revocationSource;
    public Boolean revocationEvidenceValid;
    public Boolean revocationFresh;
    public String revocationCheckedAt;
    public String revocationThisUpdate;
    public String revocationNextUpdate;
    public String revocationIndeterminateReason;

    // Carimbo do tempo
    public Boolean timestampPresent;
    public Boolean timestampValid;
    public String timestampAuthority;
    public String timestampTime;

    // Política de assinatura
    public String policyOid;
    public String policyName;
    public Boolean policyDeclared;
    public Boolean policyRecognized;

    public static SignatureValidationResult error(String message) {
        SignatureValidationResult result = new SignatureValidationResult();

        result.ok = false;
        result.result = "validation_error";

        result.hasSignature = false;
        result.valid = false;
        result.icpBrasil = false;

        result.govBr = false;
        result.govBrAdvanced = false;
        result.govBrIssuerDetected = false;
        result.govBrIssuerMatchedBy = null;
        result.govBrValidationStatus = null;
        result.govBrMessage = null;

        result.standard = null;
        result.validationLevel = "error";
        result.message = message;

        result.signatureIntegrityValid = false;
        result.byteRangeValid = false;
        result.finalDocumentCovered = false;
        result.finalDocumentAcceptable = false;
        result.postSignatureUpdateDetected = false;
        result.postSignatureUpdateAccepted = false;
        result.postSignatureUpdateType = null;
        result.postSignatureUpdateBytes = null;
        result.postSignatureUpdateMessage = null;

        result.chainValid = false;
        result.trustAnchor = null;

        result.revocationChecked = false;
        result.revocationMethod = null;
        result.revoked = null;
        result.crlUrl = null;
        result.crlIssuer = null;
        result.crlThisUpdate = null;
        result.crlNextUpdate = null;
        result.revocationDate = null;
        result.revocationReason = null;
        result.ocspUrl = null;
        result.ocspStatus = null;
        result.ocspResponder = null;
        result.ocspProducedAt = null;
        result.ocspThisUpdate = null;
        result.ocspNextUpdate = null;

        result.revocationStatus = "not_checked";
        result.revocationSource = null;
        result.revocationEvidenceValid = false;
        result.revocationFresh = false;
        result.revocationCheckedAt = null;
        result.revocationThisUpdate = null;
        result.revocationNextUpdate = null;
        result.revocationIndeterminateReason = message;

        result.timestampPresent = null;
        result.timestampValid = null;
        result.timestampAuthority = null;
        result.timestampTime = null;

        result.policyOid = null;
        result.policyName = null;
        result.policyDeclared = false;
        result.policyRecognized = false;

        result.signatureCount = 0;
        result.validSignatureCount = 0;
        result.invalidSignatureCount = 0;
        result.indeterminateSignatureCount = 0;
        result.govBrSignatureCount = 0;
        result.govBrValidSignatureCount = 0;
        result.govBrInvalidSignatureCount = 0;
        result.govBrIndeterminateSignatureCount = 0;
        result.icpBrasilSignatureCount = 0;

        result.errors.add(message);

        return result;
    }
}
