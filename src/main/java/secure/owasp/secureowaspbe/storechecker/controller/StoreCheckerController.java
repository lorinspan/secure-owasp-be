package secure.owasp.secureowaspbe.storechecker.controller;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import secure.owasp.secureowaspbe.storechecker.service.StoreCheckerService;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;

import java.util.Map;

@RestController
@RequestMapping("/api/store-checker")
@RequiredArgsConstructor
public class StoreCheckerController {

    private static final Logger logger = LoggerFactory.getLogger(StoreCheckerController.class);
    private final StoreCheckerService storeCheckerService;

    @PostMapping("/check-stock")
    public ResponseEntity<?> checkStock(@RequestBody Map<String, String> request) {
        String storeUrl = request.get("url");
        logger.info("Received request to check stock for URL: {}", storeUrl);

        try {
            Map<String, String> response = storeCheckerService.checkStock(storeUrl);
            logger.info("Successfully retrieved stock data for: {}", storeUrl);
            return ResponseEntity.ok(response);

        } catch (SecurityException e) {
            logger.warn("Blocked SSRF attempt for URL: {}", storeUrl);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));

        } catch (HttpClientErrorException | ResourceAccessException e) {
            logger.error("Forbidden access to external URL: {} | Reason: {}", storeUrl, e.getMessage());
            return ResponseEntity.status(403).body(Map.of("error", "Access to this store is restricted or unavailable."));

        } catch (Exception e) {
            logger.error("Unexpected error while fetching store data: {}", e.getMessage());
            return ResponseEntity.status(500).body(Map.of("error", "Could not retrieve store data. Please try again later."));
        }
    }
}
