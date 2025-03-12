package secure.owasp.secureowaspbe.authentication.admin.controller;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import secure.owasp.secureowaspbe.authentication.admin.service.AdminService;

import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private static final Logger logger = LoggerFactory.getLogger(AdminController.class);
    private final AdminService adminService;

    @GetMapping("/config")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> getAdminConfig() {
        return adminService.getAdminConfig();
    }

    @PostMapping("/execute")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> executeCommand(@RequestBody Map<String, String> request) {
        String command = request.get("command");

        try {
            String output = adminService.executeCommand(command);
            return Map.of("output", output);
        } catch (SecurityException e) {
            logger.error("Blocked command attempt: {}", command);
            return Map.of("error", e.getMessage());
        } catch (Exception e) {
            logger.error("Error executing command: {}", e.getMessage());
            return Map.of("error", "Could not execute command.");
        }
    }
}
