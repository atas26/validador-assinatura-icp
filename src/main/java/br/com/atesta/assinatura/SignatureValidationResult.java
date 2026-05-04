package br.com.atesta.assinatura;

import java.util.ArrayList;
import java.util.List;

public class SignatureValidationResult {
    public boolean ok;
    public String result;

    public boolean hasSignature;
    public Boolean valid;
    public Boolean icpBrasil;

    public String standard;
    public String validationLevel;
    public String message;

    public List<String> warnings = new ArrayList<>();
    public List<String> errors = new ArrayList<>();
    public List<SignatureInfo> signatures = new ArrayList<>();

    // Integridade da assinatura
    public Boolean signatureIntegrityValid;
    public Boolean byteRangeValid;

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

    // Carimbo do tempo
    public Boolean timestampPresent;
    public Boolean timestampValid;
    public String timestampAuthority;
    public String timestampTime;

    // Política de assinatura
    public String policyOid;
    public String policyName;

    public static SignatureValidationResult error(String message) {
        SignatureValidationResult result = new SignatureValidationResult();

        result.ok = false;
        result.result = "validation_error";

        result.hasSignature = false;
        result.valid = false;
        result.icpBrasil = false;

        result.standard = null;
        result.validationLevel = "error";
        result.message = message;

        result.signatureIntegrityValid = false;
        result.byteRangeValid = false;

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

        result.timestampPresent = null;
        result.timestampValid = null;
        result.timestampAuthority = null;
        result.timestampTime = null;

        result.policyOid = null;
        result.policyName = null;

        result.errors.add(message);

        return result;
    }
}
