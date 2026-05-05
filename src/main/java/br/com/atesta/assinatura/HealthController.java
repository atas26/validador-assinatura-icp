package br.com.atesta.assinatura;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class HealthController {

    @GetMapping("/api/health")
    public Map<String, Object> health() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("ok", true);
        response.put("service", "validador-assinatura-icp");
        response.put("mode", "demoiselle-pades-poc");
        response.put("timestamp", Instant.now().toString());
        return response;
    }

    @GetMapping("/api/status")
    public Map<String, Object> status() {
        Map<String, Object> response = new LinkedHashMap<>();

        response.put("ok", true);
        response.put("service", "validador-assinatura-icp");
        response.put("mode", "demoiselle-pades-poc");
        response.put("timestamp", Instant.now().toString());

        Map<String, Object> endpoints = new LinkedHashMap<>();
        endpoints.put("health", "/api/health");
        endpoints.put("status", "/api/status");
        endpoints.put("validateSignature", "/api/validate-signature");
        response.put("endpoints", endpoints);

        Map<String, Object> features = new LinkedHashMap<>();
        features.put("signatureValidation", true);
        features.put("pdfSignatureDetection", true);
        features.put("pades", true);
        features.put("icpBrasilCertificateDetection", true);
        features.put("icpBrasilChainValidation", true);
        features.put("revocationValidation", true);
        features.put("revocationMethods", Arrays.asList("OCSP", "CRL"));
        features.put("byteRangeValidation", true);
        features.put("signedRevisionIntegrity", true);
        features.put("finalDocumentCoverageCheck", true);
        features.put("incrementalUpdateClassification", true);
        features.put("dssVriDetection", true);
        features.put("timestampDetection", true);
        features.put("policyMapping", true);
        response.put("features", features);

        Map<String, Object> notes = new LinkedHashMap<>();
        notes.put("purpose", "Endpoint técnico para verificar se o serviço de validação de assinatura está operacional.");
        notes.put("scope", "Este endpoint não valida documento. A validação efetiva ocorre apenas em /api/validate-signature.");
        notes.put("legalUse", "O status operacional do serviço não substitui a análise técnica do PDF enviado nem a qualificação jurídica do documento.");
        response.put("notes", notes);

        return response;
    }
}
