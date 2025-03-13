package secure.owasp.secureowaspbe.authentication.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import secure.owasp.secureowaspbe.authentication.user.model.User;
import secure.owasp.secureowaspbe.authentication.user.repository.UserRepository;
import secure.owasp.secureowaspbe.security.jwt.JwtUtil;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.when;

public class AuthServiceTest {

    @InjectMocks
    private AuthService authService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private BCryptPasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void login_Success_ReturnsToken() {
        User user = new User();
        user.setUsername("testUser");
        user.setRole("USER");

        when(userRepository.findByUsername("testUser")).thenReturn(Optional.of(user));
        when(jwtUtil.generateToken("testUser", "USER")).thenReturn("valid-token");

        String token = authService.login("testUser", "password");

        assertEquals("valid-token", token);
    }

    @Test
    void login_InvalidCredentials_ThrowsException() {
        when(userRepository.findByUsername("testUser")).thenReturn(Optional.empty());

        assertThrows(IllegalArgumentException.class, () -> authService.login("testUser", "wrongPass"));
    }

    @Test
    void register_Success_ReturnsUser() {
        User newUser = new User();
        newUser.setUsername("newUser");
        newUser.setEmail("new@example.com");
        newUser.setPassword("aaAA11!!");

        when(userRepository.existsByUsername("newUser")).thenReturn(false);
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(passwordEncoder.encode("securePass")).thenReturn("encodedPass");
        when(userRepository.save(any(User.class))).thenReturn(newUser);

        User result = authService.register(newUser);

        assertEquals("newUser", result.getUsername());
        assertEquals("new@example.com", result.getEmail());
    }
}
