package br.com.atesta.assinatura;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;

@Service
public class SignatureValidationService {
    private static final int MAX_BYTES = 50 * 1024 * 1024;

    public SignatureValidationResult validate(MultipartFile file) {
        try {
            if (file == null || file.isEmpty()) {
                return error("Arquivo ausente ou vazio.");
            }

            if (file.getSize() > MAX_BYTES) {
                return error("Arquivo maior que o limite de 50 MB.");
            }

            byte[] bytes = file.getBytes();
            if (!looksLikePdf(bytes)) {
                return error("O arquivo enviado não parece ser PDF.");
            }

            try (PDDocument document = Loader.loadPDF(bytes)) {
                List<PDSignature> dictionaries = document.getSignatureDictionaries();

                if (dictionaries == null || dictionaries.isEmpty()) {
                    return new SignatureValidationResult(
                            true,
                            "not_signed",
                            false,
                            false,
                            false,
                            null,
                            "preliminary_detection",
                            "Assinatura digital embutida no PDF não localizada.",
                            List.of("Esta versão base detecta assinaturas embutidas no PDF. A validação ICP-Brasil completa será plugada na fase Demoiselle."),
                            List.of()
                    );
                }

                List<SignatureInfo> infos = new ArrayList<>();
                int index = 1;
                boolean padesLikely = false;

                for (PDSignature sig : dictionaries) {
                    String subFilter = safe(sig.getSubFilter());
                    boolean currentPades = isPadesLike(subFilter);
                    padesLikely = padesLikely || currentPades;

                    infos.add(new SignatureInfo(
                            index++,
                            safe(sig.getName()),
                            safe(sig.getReason()),
                            safe(sig.getLocation()),
                            safe(sig.getContactInfo()),
                            formatCalendar(sig.getSignDate()),
                            safe(sig.getFilter()),
                            subFilter,
                            currentPades
                    ));
                }

                return new SignatureValidationResult(
                        true,
                        "signature_detected",
                        true,
                        null,
                        null,
                        padesLikely ? "PAdES provável" : "PDF signature",
                        "preliminary_detection",
                        "Assinatura digital embutida localizada. Esta etapa identifica a assinatura, mas ainda não valida cadeia ICP-Brasil, revogação, política ICP-Brasil ou integridade criptográfica completa.",
                        List.of("Não use este retorno como validação ICP-Brasil definitiva. Próxima fase: integrar Demoiselle Signer."),
                        infos
                );
            }
        } catch (IOException ex) {
            return error("Falha ao ler o PDF: " + ex.getMessage());
        } catch (Exception ex) {
            return error("Falha inesperada na análise da assinatura: " + ex.getMessage());
        }
    }

    private SignatureValidationResult error(String message) {
        return new SignatureValidationResult(
                false,
                "error",
                false,
                false,
                false,
                null,
                "preliminary_detection",
                message,
                List.of(),
                List.of()
        );
    }

    private boolean looksLikePdf(byte[] bytes) {
        if (bytes.length < 5) {
            return false;
        }
        return bytes[0] == '%' && bytes[1] == 'P' && bytes[2] == 'D' && bytes[3] == 'F' && bytes[4] == '-';
    }

    private boolean isPadesLike(String subFilter) {
        if (subFilter == null) {
            return false;
        }
        String value = subFilter.toLowerCase(Locale.ROOT);
        return value.contains("pkcs7") || value.contains("cades") || value.contains("etsi");
    }

    private String safe(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private String formatCalendar(Calendar calendar) {
        if (calendar == null) {
            return null;
        }
        return DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(calendar.toInstant().atOffset(ZoneOffset.UTC));
    }
}
