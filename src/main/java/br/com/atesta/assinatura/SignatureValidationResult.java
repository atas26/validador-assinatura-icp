package br.com.atesta.assinatura;

import java.util.List;

public record SignatureValidationResult(
        boolean ok,
        String result,
        boolean hasSignature,
        Boolean valid,
        Boolean icpBrasil,
        String standard,
        String validationLevel,
        String message,
        List<String> warnings,
        List<SignatureInfo> signatures
) {}
