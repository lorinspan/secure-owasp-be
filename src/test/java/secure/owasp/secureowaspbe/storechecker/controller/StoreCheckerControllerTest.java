package secure.owasp.secureowaspbe.storechecker.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.OK;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;
import secure.owasp.secureowaspbe.storechecker.service.StoreCheckerService;

import java.util.Map;

public class StoreCheckerControllerTest {

    @InjectMocks
    private StoreCheckerController storeCheckerController;

    @Mock
    private StoreCheckerService storeCheckerService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void checkStock_Success() {
        String storeUrl = "emag";
        Map<String, String> mockResponse = Map.of("message", "Iphone 13 Mini: 10 bucăți");

        when(storeCheckerService.checkStock(storeUrl)).thenReturn(mockResponse);

        ResponseEntity<?> response = storeCheckerController.checkStock(Map.of("url", storeUrl));

        assertEquals(OK, response.getStatusCode());
        assertEquals(mockResponse, response.getBody());
    }

    @Test
    void checkStock_SecurityException() {
        String storeUrl = "malicious-site";
        when(storeCheckerService.checkStock(storeUrl)).thenThrow(new SecurityException("Blocked SSRF attempt"));

        ResponseEntity<?> response = storeCheckerController.checkStock(Map.of("url", storeUrl));

        assertEquals(BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("Blocked SSRF attempt"));
    }
}
