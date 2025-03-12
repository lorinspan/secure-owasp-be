package secure.owasp.secureowaspbe.security.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import secure.owasp.secureowaspbe.authentication.user.model.User;
import secure.owasp.secureowaspbe.authentication.user.repository.UserRepository;

import java.util.Optional;

public class UserDServiceTest {

    @InjectMocks
    private UserDService userDService;

    @Mock
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void loadUserByUsername_UserExists() {
        User mockUser = new User();
        mockUser.setUsername("testUser");
        mockUser.setPassword("encodedPassword");
        mockUser.setRole("USER");

        when(userRepository.findByUsername("testUser")).thenReturn(Optional.of(mockUser));

        UserDetails userDetails = userDService.loadUserByUsername("testUser");

        assertEquals("testUser", userDetails.getUsername());
        assertEquals("encodedPassword", userDetails.getPassword());
    }

    @Test
    void loadUserByUsername_UserNotFound() {
        when(userRepository.findByUsername("unknownUser")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () -> userDService.loadUserByUsername("unknownUser"));
    }
}
