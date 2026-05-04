package br.com.atesta.assinatura;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {
    @GetMapping("/api/health")
    public Map<String, Object> health() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "demoiselle-pades-poc");
        out.put("ok", true);
        out.put("service", "validador-assinatura-icp");
        out.put("timestamp", Instant.now().toString());
        return out;
    }
}
