package secure.owasp.secureowaspbe.authentication.admin.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AdminServiceTest {

    private AdminService adminService;

    MockedStatic<SecurityContextHolder> mockedSecurityContextHolder;

    @BeforeEach
    void setUp() {
        adminService = new AdminService();

        mockedSecurityContextHolder = Mockito.mockStatic(SecurityContextHolder.class);
        SecurityContext securityContext = mock(SecurityContext.class);
        Authentication authentication = mock(Authentication.class);

        when(authentication.getName()).thenReturn("adminUser");
        when(securityContext.getAuthentication()).thenReturn(authentication);
        mockedSecurityContextHolder.when(SecurityContextHolder::getContext).thenReturn(securityContext);
    }

    @AfterEach
    void after() {
        mockedSecurityContextHolder.close();
    }

    @Test
    void executeCommand_BlacklistedCommand_ThrowsSecurityException() {
        String command = "rm -rf /";
        assertThrows(SecurityException.class, () -> adminService.executeCommand(command));
    }

    @Test
    void executeCommand_InvalidCommand_ReturnsError() {
        String command = "invalidCommand";

        String output = adminService.executeCommand(command);

        assertEquals("Error executing command!", output);
    }
}
