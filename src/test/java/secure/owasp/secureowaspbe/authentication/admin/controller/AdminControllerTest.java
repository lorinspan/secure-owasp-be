package secure.owasp.secureowaspbe.authentication.admin.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import secure.owasp.secureowaspbe.authentication.admin.service.AdminService;

import java.util.Map;

public class AdminControllerTest {

    @InjectMocks
    private AdminController adminController;

    @Mock
    private AdminService adminService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getAdminConfig_ReturnsConfig() {
        Map<String, String> mockConfig = Map.of(
                "ALLOWED_ORIGINS", "http://localhost",
                "DB_URL", "jdbc:mysql://localhost:3306/mydb",
                "DB_USERNAME", "admin",
                "JWT_SECRET", "********"
        );

        when(adminService.getAdminConfig()).thenReturn(mockConfig);

        Map<String, String> response = adminController.getAdminConfig();

        assertEquals(mockConfig, response);
    }

    @Test
    void executeCommand_ValidCommand_ReturnsOutput() {
        String command = "ls -la";
        when(adminService.executeCommand(command)).thenReturn("command output");

        Map<String, String> response = adminController.executeCommand(Map.of("command", command));

        assertEquals("command output", response.get("output"));
    }

    @Test
    void executeCommand_BlacklistedCommand_ReturnsError() {
        String command = "rm -rf /";
        when(adminService.executeCommand(command)).thenThrow(new SecurityException("Execution of this command is not allowed for security reasons!"));

        Map<String, String> response = adminController.executeCommand(Map.of("command", command));

        assertTrue(response.containsKey("error"));
        assertEquals("Execution of this command is not allowed for security reasons!", response.get("error"));
    }

    @Test
    void executeCommand_Exception_ReturnsErrorMessage() {
        String command = "unknownCommand";
        when(adminService.executeCommand(command)).thenThrow(new RuntimeException("Execution error"));

        Map<String, String> response = adminController.executeCommand(Map.of("command", command));

        assertTrue(response.containsKey("error"));
        assertEquals("Could not execute command.", response.get("error"));
    }
}
