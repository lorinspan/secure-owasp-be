package secure.owasp.secureowaspbe.authentication.admin.service;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AdminService {

    private static final Logger logger = LoggerFactory.getLogger(AdminService.class);

    private static final List<String> BLACKLISTED_COMMANDS = List.of(
            "rm", "sudo", "shutdown", "reboot", "halt", "poweroff", "mkfs", "dd",
            "kill", "pkill", "wget", "curl", "nc", "netcat", "nmap", "iptables",
            "chmod", "chown", "mv", "rmdir", "unlink", "scp", "rsync", "echo"
    );

    public Map<String, String> getAdminConfig() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();

        logger.info("Admin [{}] accessed configuration settings", username);

        return Map.of(
                "ALLOWED_ORIGINS", System.getenv("ALLOWED_ORIGINS"),
                "DB_URL", System.getenv("DB_URL"),
                "DB_USERNAME", System.getenv("DB_USERNAME"),
                "JWT_SECRET", "********" // Simulam ca nici administratorii nu ar trebui sa aiba acces la aceasta variabila - doar dezvoltatorii.
        );
    }

    public String executeCommand(String command) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();

        logger.info("Admin [{}] requested command execution: {}", username, command);

        if (isBlacklisted(command)) {
            logger.warn("Blocked execution of dangerous command by Admin [{}]: {}", username, command);
            throw new SecurityException("Execution of this command is not allowed for security reasons!");
        }

        String output = runShellCommand(command);

        if (output.equals("Error executing command!")) {
            logger.error("Admin [{}] encountered an error while executing: {}", username, command);
        } else {
            logger.info("Admin [{}] executed command successfully: {}", username, command);
        }

        return output;
    }

    private String runShellCommand(String command) {
        StringBuilder output = new StringBuilder();

        try {
            Process process = new ProcessBuilder(command.split(" ")).start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            if (output.toString().trim().isEmpty()) {
                return "Command executed successfully, but no output was returned.";
            }

        } catch (Exception e) {
            logger.error("Error executing command [{}]: {}", command, e.getMessage());
            return "Error executing command!";
        }

        return output.toString().trim();
    }

    private boolean isBlacklisted(String command) {
        String[] tokens = command.split("\\s+");
        for (String token : tokens) {
            if (BLACKLISTED_COMMANDS.contains(token)) {
                return true;
            }
        }
        return false;
    }
}