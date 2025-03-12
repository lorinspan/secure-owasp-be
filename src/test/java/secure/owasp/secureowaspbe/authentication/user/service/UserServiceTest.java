package secure.owasp.secureowaspbe.authentication.user.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import secure.owasp.secureowaspbe.authentication.user.model.User;
import secure.owasp.secureowaspbe.authentication.user.repository.UserRepository;
import secure.owasp.secureowaspbe.security.jwt.JwtUtil;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.when;

public class UserServiceTest {

    @InjectMocks
    private UserService userService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private BCryptPasswordEncoder passwordEncoder;

    @Mock
    private Authentication authentication;

    @Mock
    private SecurityContext securityContext;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getName()).thenReturn("adminUser");
        SecurityContextHolder.setContext(securityContext);
    }

    @Test
    void getUserByUsername_Success() {
        User mockUser = new User();
        mockUser.setUsername("testUser");
        when(userRepository.findByUsername("testUser")).thenReturn(Optional.of(mockUser));

        Optional<User> result = userService.getUserByUsername("testUser");

        assertTrue(result.isPresent());
        assertEquals("testUser", result.get().getUsername());
    }

    @Test
    void updateUser_Success() {
        User mockUser = new User();
        mockUser.setUsername("testUser");
        when(userRepository.findByUsername("testUser")).thenReturn(Optional.of(mockUser));
        when(userRepository.save(any(User.class))).thenReturn(mockUser);

        Map<String, String> updates = Map.of("email", "new@example.com");
        Map<String, Object> result = userService.updateUser("testUser", updates);

        assertNotNull(result);
        assertTrue(result.containsKey("user"));
    }

    @Test
    void updateUserByAdmin_Success() {
        User mockAdmin = new User();
        mockAdmin.setUsername("adminUser");
        when(userRepository.findByUsername("adminUser")).thenReturn(Optional.of(mockAdmin));

        User mockUser = new User();
        mockUser.setUsername("testUser");
        when(userRepository.findById(1L)).thenReturn(Optional.of(mockUser));
        when(userRepository.save(any(User.class))).thenReturn(mockUser);

        Map<String, String> updates = Map.of("role", "ADMIN");
        User updatedUser = userService.updateUserByAdmin(1L, updates);

        assertEquals("testUser", updatedUser.getUsername());
    }

    @Test
    void updateUserByAdmin_CannotChangeOwnRole() {
        User mockAdmin = new User();
        mockAdmin.setUsername("adminUser");
        when(userRepository.findByUsername("adminUser")).thenReturn(Optional.of(mockAdmin));

        assertThrows(IllegalArgumentException.class, () -> userService.updateUserByAdmin(1L, Map.of("role", "USER")));
    }
}
