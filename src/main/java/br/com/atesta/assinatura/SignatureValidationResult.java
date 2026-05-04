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
        result.errors.add(message);
        return result;
    }
}
