package br.com.atesta.assinatura;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
public class HealthController {
    @GetMapping("/api/health")
    public Map<String, Object> health() {
        return Map.of(
                "ok", true,
                "service", "validador-assinatura-icp",
                "mode", "microservico-java-base",
                "timestamp", Instant.now().toString()
        );
    }
}
