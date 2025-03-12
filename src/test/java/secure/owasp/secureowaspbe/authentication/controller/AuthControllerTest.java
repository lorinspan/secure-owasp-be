package secure.owasp.secureowaspbe.authentication.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;
import secure.owasp.secureowaspbe.authentication.service.AuthService;
import secure.owasp.secureowaspbe.authentication.user.model.User;

import java.util.Map;

public class AuthControllerTest {

    @InjectMocks
    private AuthController authController;

    @Mock
    private AuthService authService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void login_Success_ReturnsToken() {
        String username = "testUser";
        String password = "testPass";
        when(authService.login(username, password)).thenReturn("valid-token");

        ResponseEntity<?> response = authController.login(Map.of("username", username, "password", password));

        assertEquals(OK, response.getStatusCode());
        assertEquals("valid-token", ((Map<?, ?>) response.getBody()).get("token"));
    }

    @Test
    void login_InvalidCredentials_ReturnsUnauthorized() {
        String username = "testUser";
        String password = "wrongPass";
        when(authService.login(username, password)).thenThrow(new IllegalArgumentException("Invalid username or password!"));

        ResponseEntity<?> response = authController.login(Map.of("username", username, "password", password));

        assertEquals(UNAUTHORIZED, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("Invalid username or password!"));
    }

    @Test
    void login_TooManyAttempts_ReturnsUnauthorized() {
        String username = "testUser";
        String password = "testPass";
        when(authService.login(username, password)).thenThrow(new IllegalArgumentException("Too many failed attempts. Please try again later."));

        ResponseEntity<?> response = authController.login(Map.of("username", username, "password", password));

        assertEquals(UNAUTHORIZED, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("Too many failed attempts"));
    }

    @Test
    void register_Success_ReturnsUser() {
        User newUser = new User();
        newUser.setUsername("testUser");
        newUser.setEmail("test@example.com");
        newUser.setPassword("securePass");

        when(authService.register(newUser)).thenReturn(newUser);

        ResponseEntity<?> response = authController.register(newUser);

        assertEquals(OK, response.getStatusCode());
        assertEquals(newUser, response.getBody());
    }

    @Test
    void register_UserAlreadyExists_ReturnsBadRequest() {
        User newUser = new User();
        newUser.setUsername("existingUser");
        newUser.setEmail("existing@example.com");
        newUser.setPassword("securePass");

        when(authService.register(newUser)).thenThrow(new IllegalArgumentException("Username already exists!"));

        ResponseEntity<?> response = authController.register(newUser);

        assertEquals(BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("Username already exists"));
    }
}
