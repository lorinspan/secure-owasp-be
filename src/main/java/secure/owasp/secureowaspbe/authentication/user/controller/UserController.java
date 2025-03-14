package secure.owasp.secureowaspbe.authentication.user.controller;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import secure.owasp.secureowaspbe.authentication.user.model.User;
import secure.owasp.secureowaspbe.authentication.user.model.UserDto;
import secure.owasp.secureowaspbe.authentication.user.service.UserService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService;

    @GetMapping("/me")
    public ResponseEntity<?> getLoggedInUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        logger.info("User {} accessed their profile", username);
        Optional<User> user = userService.getUserByUsername(username);
        return user.map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PutMapping("/me/update")
    public ResponseEntity<?> updateUserDetails(@RequestBody Map<String, String> updates) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String oldUsername = auth.getName();

        logger.info("User {} requested an update", oldUsername);

        try {
            Map<String, Object> response = userService.updateUser(oldUsername, updates);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            logger.error("Error updating user {}: {}", oldUsername, e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }


    @GetMapping("/all")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        logger.info("Admin accessed all users");
        List<UserDto> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateUserByAdmin(@PathVariable Long id, @RequestBody Map<String, String> updates) {
        try {
            UserDto updatedUser = userService.updateUserByAdmin(id, updates);
            return ResponseEntity.ok(updatedUser);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')") // Ensure only admins can delete users
    public ResponseEntity<String> deleteUser(@PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String adminUsername = auth.getName();

        try {
            userService.deleteUser(id, adminUsername);
            logger.info("Admin [{}] successfully deleted user with ID [{}]", adminUsername, id);
            return ResponseEntity.ok("User deleted successfully.");
        } catch (IllegalArgumentException e) {
            logger.warn("Admin [{}] attempted to delete user [{}] but failed: {}", adminUsername, id, e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
