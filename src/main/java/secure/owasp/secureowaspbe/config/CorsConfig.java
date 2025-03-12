package secure.owasp.secureowaspbe.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Configuration
public class CorsConfig {

    private static final Logger logger = LoggerFactory.getLogger(CorsConfig.class);

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Preluam variabila de mediu
        String allowedOriginsEnv = System.getenv("ALLOWED_ORIGINS");

        // In cazul in care este o lista (localhost:4200, localhost:4201, etc), convertim intr-o lista
        List<String> allowedOrigins = Optional.ofNullable(allowedOriginsEnv)
                .map(origins -> Arrays.asList(origins.split(",")))
                .orElse(List.of());

        logger.info("CORS Config Loaded - Allowed Origins: {}", allowedOrigins);

        configuration.setAllowedOrigins(allowedOrigins);
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        configuration.setAllowCredentials(true); // Permitem credentiale doar daca este necesar

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
