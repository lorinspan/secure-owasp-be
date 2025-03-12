package secure.owasp.secureowaspbe.authentication.user.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import secure.owasp.secureowaspbe.authentication.user.model.User;
import secure.owasp.secureowaspbe.authentication.user.model.UserDto;
import secure.owasp.secureowaspbe.authentication.user.service.UserService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

public class UserControllerTest {

    @InjectMocks
    private UserController userController;

    @Mock
    private UserService userService;

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
    void getLoggedInUser_Success() {
        User mockUser = new User();
        mockUser.setUsername("testUser");
        when(userService.getUserByUsername("testUser")).thenReturn(Optional.of(mockUser));

        ResponseEntity<?> response = userController.getLoggedInUser();

        assertEquals(OK, response.getStatusCode());
        assertEquals(mockUser, response.getBody());
    }

    @Test
    void getLoggedInUser_NotFound() {
        when(userService.getUserByUsername("testUser")).thenReturn(Optional.empty());

        ResponseEntity<?> response = userController.getLoggedInUser();

        assertEquals(NOT_FOUND, response.getStatusCode());
    }

    @Test
    void updateUserDetails_Success() {
        Map<String, String> updates = Map.of("email", "new@example.com");
        Map<String, Object> mockResponse = Map.of("user", new User());

        when(userService.updateUser("testUser", updates)).thenReturn(mockResponse);

        ResponseEntity<?> response = userController.updateUserDetails(updates);

        assertEquals(OK, response.getStatusCode());
        assertEquals(mockResponse, response.getBody());
    }

    @Test
    void updateUserDetails_Error() {
        Map<String, String> updates = Map.of("email", "existing@example.com");
        when(userService.updateUser("testUser", updates)).thenThrow(new IllegalArgumentException("Email already taken"));

        ResponseEntity<?> response = userController.updateUserDetails(updates);

        assertEquals(BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("Email already taken"));
    }

    @Test
    void getAllUsers_ReturnsList() {
        List<UserDto> mockUsers = List.of(new UserDto(1L, "user1", "email1", "USER", null, null));
        when(userService.getAllUsers()).thenReturn(mockUsers);

        ResponseEntity<List<UserDto>> response = userController.getAllUsers();

        assertEquals(OK, response.getStatusCode());
        assertEquals(mockUsers, response.getBody());
    }

    @Test
    void updateUserByAdmin_Success() {
        Map<String, String> updates = Map.of("role", "ADMIN");
        User mockUser = new User();
        mockUser.setUsername("updatedUser");

        when(userService.updateUserByAdmin(1L, updates)).thenReturn(mockUser);

        ResponseEntity<?> response = userController.updateUserByAdmin(1L, updates);

        assertEquals(OK, response.getStatusCode());
        assertEquals(mockUser, response.getBody());
    }

    @Test
    void updateUserByAdmin_Error() {
        Map<String, String> updates = Map.of("role", "ADMIN");
        when(userService.updateUserByAdmin(1L, updates)).thenThrow(new IllegalArgumentException("Cannot change own role"));

        ResponseEntity<?> response = userController.updateUserByAdmin(1L, updates);

        assertEquals(BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("Cannot change own role"));
    }
}
