package secure.owasp.secureowaspbe.storechecker.service;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class StoreCheckerService {

    private static final Logger logger = LoggerFactory.getLogger(StoreCheckerService.class);
    private final RestTemplate restTemplate;

    // Mapam fiecare substring catre date hardcodate despre stocuri pentru a simula un serviciu de verificare stoc prin introducere de URL-uri
    private static final Map<String, String> ALLOWED_URLS = Map.of(
            "emag", "Iphone 13 Mini: 10 bucăți, Purificatoare Dyson: 5 bucăți",
            "media-galaxy", "Iphone 13 Mini: 3 bucăți, Purificatoare Dyson: 8 bucăți",
            "altex", "Iphone 13 Mini: 6 bucăți, Purificatoare Dyson: 2 bucăți",
            "cel", "Iphone 13 Mini: 12 bucăți, Purificatoare Dyson: 15 bucăți",
            "avstore", "Iphone 13 Mini: 7 bucăți, Purificatoare Dyson: 4 bucăți"
    );

    public Map<String, String> checkStock(String storeUrl) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();

        // Cauta magazinul potrivit pe baza substring-ului
        String stockInfo = getAllowedStockData(storeUrl);

        if (stockInfo != null) {
            logger.info("✅ User [{}] checked stock for [{}]: {}", username, storeUrl, stockInfo);
            return Map.of("message", stockInfo);
        }

        // Daca magazinul nu este in lista alba, incercam un request HTTP real
        // In cazul unei aplicatii reale, se realiza un request HTTP in fiecare caz de whitelist
        try {
            logger.warn("User [{}] is requesting external store URL: {}", username, storeUrl);
            String response = restTemplate.getForObject(storeUrl, String.class);

            logger.warn("User [{}] attempted to access a forbidden store URL: {}", username, storeUrl);
            throw new SecurityException("Access to this store is restricted or unavailable.");

//            return Map.of("message", response);
            // Cod comentat pentru ca aici simulam comportamentul, nu realizam cu adevarat un request HTTP
        } catch (HttpClientErrorException | ResourceAccessException e) {
            logger.error("Failed to access external store URL [{}]: {}", storeUrl, e.getMessage());
            return Map.of("error", "Access to this store is restricted or unavailable.");
        }
    }
    private String getAllowedStockData(String storeUrl) {
        return ALLOWED_URLS.entrySet().stream()
                .filter(entry -> storeUrl.toLowerCase().contains(entry.getKey()))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(null);
    }
}
