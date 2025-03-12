package secure.owasp.secureowaspbe.storechecker.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

public class StoreCheckerServiceTest {

    @InjectMocks
    private StoreCheckerService storeCheckerService;

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private Authentication authentication;

    @Mock
    private SecurityContext securityContext;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getName()).thenReturn("testUser");
        SecurityContextHolder.setContext(securityContext);
    }

    @Test
    void checkStock_AllowedStore_ReturnsStockInfo() {
        String storeUrl = "https://www.emag.ro";

        Map<String, String> result = storeCheckerService.checkStock(storeUrl);

        assertNotNull(result);
        assertTrue(result.get("message").contains("Iphone 13 Mini"));
    }

    @Test
    void checkStock_ExternalURL_ThrowsSecurityException() {
        String storeUrl = "https://malicious-site.com";

        when(restTemplate.getForObject(storeUrl, String.class)).thenReturn("Fake response");

        SecurityException exception = assertThrows(SecurityException.class, 
            () -> storeCheckerService.checkStock(storeUrl));

        assertEquals("Access to this store is restricted or unavailable.", exception.getMessage());
    }

    @Test
    void checkStock_ExternalURL_ThrowsHttpClientErrorException() {
        String storeUrl = "https://unknown-store.com";

        when(restTemplate.getForObject(storeUrl, String.class))
                .thenThrow(HttpClientErrorException.Forbidden.class);

        Map<String, String> result = storeCheckerService.checkStock(storeUrl);

        assertTrue(result.containsKey("error"));
        assertEquals("Access to this store is restricted or unavailable.", result.get("error"));
    }

    @Test
    void checkStock_ExternalURL_ThrowsResourceAccessException() {
        String storeUrl = "https://offline-store.com";

        when(restTemplate.getForObject(storeUrl, String.class))
                .thenThrow(new ResourceAccessException("Network issue"));

        Map<String, String> result = storeCheckerService.checkStock(storeUrl);

        assertTrue(result.containsKey("error"));
        assertEquals("Access to this store is restricted or unavailable.", result.get("error"));
    }
}
