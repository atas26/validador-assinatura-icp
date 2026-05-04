package br.com.atesta.assinatura;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class SignatureController {
    private final SignatureValidationService validationService;

    public SignatureController(SignatureValidationService validationService) {
        this.validationService = validationService;
    }

    @PostMapping(value = "/api/validate-signature", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<SignatureValidationResult> validateSignature(@RequestParam("file") MultipartFile file) {
        SignatureValidationResult result = validationService.validate(file);
        return ResponseEntity.ok(result);
    }
}
