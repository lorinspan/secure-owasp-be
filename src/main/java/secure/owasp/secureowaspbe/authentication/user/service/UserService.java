package secure.owasp.secureowaspbe.authentication.user.service;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import secure.owasp.secureowaspbe.authentication.user.model.User;
import secure.owasp.secureowaspbe.authentication.user.model.UserDto;
import secure.owasp.secureowaspbe.authentication.user.repository.UserRepository;
import secure.owasp.secureowaspbe.security.jwt.JwtUtil;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public Optional<User> getUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public List<UserDto> getAllUsers() {
        List<User> users = userRepository.findAll();

        // Convertim User in UserDto pentru a exclude parola din raspuns
        return users.stream()
                .map(user -> new UserDto(
                        user.getId(),
                        user.getUsername(),
                        user.getEmail(),
                        user.getRole(),
                        user.getCreatedAt(),
                        user.getUpdatedAt()))
                .toList();
    }

    public Map<String, Object> updateUser(String oldUsername, Map<String, String> updates) {
        User user = userRepository.findByUsername(oldUsername)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        logger.info("User [{}] (ID: {}) is updating their profile", user.getUsername(), user.getId());

        boolean usernameChanged = false;

        if (updates.containsKey("email")) {
            String newEmail = updates.get("email");
            if (userRepository.existsByEmail(newEmail)) {
                logger.warn("User [{}] (ID: {}) tried to update to an already used email: {}", user.getUsername(), user.getId(), newEmail);
                throw new IllegalArgumentException("Email already taken!");
            }
            user.setEmail(newEmail);
            logger.info("User [{}] updated email to: {}", user.getUsername(), newEmail);
        }

        if (updates.containsKey("username")) {
            String newUsername = updates.get("username");
            if (userRepository.existsByUsername(newUsername)) {
                logger.warn("User [{}] (ID: {}) tried to change to an already used username: {}", user.getUsername(), user.getId(), newUsername);
                throw new IllegalArgumentException("Username already taken!");
            }
            user.setUsername(newUsername);
            usernameChanged = true;
            logger.info("User [{}] changed username to: {}", oldUsername, newUsername);
        }

        if (updates.containsKey("password")) {
            user.setPassword(passwordEncoder.encode(updates.get("password")));
            logger.info("User [{}] updated password", user.getUsername());
        }

        User updatedUser = userRepository.save(user);

        // Daca username-ul s-a schimbat, generam un nou token si il returnam impreuna cu user-ul, deoarece login-ul se face cu username-ul
        if (usernameChanged) {
            String newToken = jwtUtil.generateToken(updatedUser.getUsername(), updatedUser.getRole());
            return Map.of("user", updatedUser, "token", newToken);
        }

        return Map.of("user", updatedUser);
    }

    public User updateUserByAdmin(Long id, Map<String, String> updates) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String adminUsername = auth.getName();

        User adminUser = userRepository.findByUsername(adminUsername)
                .orElseThrow(() -> new IllegalArgumentException("Authenticated admin user not found"));

        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        logger.info("Admin [{}] is updating user [{}] (ID: {})", adminUsername, user.getUsername(), user.getId());

        if (updates.containsKey("email")) {
            String newEmail = updates.get("email");
            if (!newEmail.equals(user.getEmail()) && userRepository.existsByEmail(newEmail)) {
                logger.warn("Admin [{}] tried to set email [{}] for user [{}] (ID: {}), but it's already taken.",
                        adminUsername, newEmail, user.getUsername(), user.getId());
                throw new IllegalArgumentException("Email already taken!");
            }
            if (!newEmail.equals(user.getEmail())) {
                user.setEmail(newEmail);
                logger.info("Admin [{}] updated email for user [{}] from [{}] to [{}]", adminUsername, user.getUsername(), user.getEmail(), newEmail);
            }
        }

        if (updates.containsKey("username")) {
            String newUsername = updates.get("username");
            if (!newUsername.equals(user.getUsername()) && userRepository.existsByUsername(newUsername)) {
                logger.warn("Admin [{}] tried to change username of user [{}] (ID: {}) to [{}], but it's already taken.",
                        adminUsername, user.getUsername(), user.getId(), newUsername);
                throw new IllegalArgumentException("Username already taken!");
            }
            if (!newUsername.equals(user.getUsername())) {
                logger.info("Admin [{}] updated username for user [{}] (ID: {}) from [{}] to [{}]",
                        adminUsername, user.getUsername(), user.getId(), user.getUsername(), newUsername);
                user.setUsername(newUsername);
            }
        }

        if (updates.containsKey("password")) {
            String newPassword = updates.get("password");
            if (!newPassword.isEmpty()) {
                user.setPassword(passwordEncoder.encode(newPassword));
                logger.info("Admin [{}] updated password for user [{}] (ID: {})", adminUsername, user.getUsername(), user.getId());
            }
        }

        // Permitem schimbarea rolului doar daca utilizatorul modificat NU este adminul autentificat
        // Pentru a evita situatia in care administratorul trebuie sa contacteze dezvoltatorul pentru recuperarea rolului de 'ADMIN'
        if (updates.containsKey("role")) {
            String newRole = updates.get("role");
            if (!newRole.equals(user.getRole())) {
                if ((user.getId() != null && adminUser.getId() != null) && user.getId().equals(adminUser.getId())) {
                    logger.warn("Admin [{}] attempted to change their own role, which is not allowed!", adminUsername);
                    throw new IllegalArgumentException("You cannot change your own role!");
                }
                user.setRole(newRole);
                logger.info("Admin [{}] changed role of user [{}] (ID: {}) from [{}] to [{}]",
                        adminUsername, user.getUsername(), user.getId(), user.getRole(), newRole);
            }
        }

        User updatedUser = userRepository.save(user);
        logger.info("Admin [{}] successfully updated user [{}] (ID: {})", adminUsername, updatedUser.getUsername(), updatedUser.getId());

        return updatedUser;
    }

    public void deleteUser(Long userId, String adminUsername) {
        User adminUser = userRepository.findByUsername(adminUsername)
                .orElseThrow(() -> new IllegalArgumentException("Authenticated admin user not found"));

        User userToDelete = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (userToDelete.getId().equals(adminUser.getId())) {
            logger.warn("Admin [{}] attempted to delete their own account, which is not allowed!", adminUsername);
            throw new IllegalArgumentException("You cannot delete your own account!");
        }

        logger.info("Admin [{}] is deleting user [{}] (ID: {})", adminUsername, userToDelete.getUsername(), userToDelete.getId());

        userRepository.delete(userToDelete);

        logger.info("User [{}] (ID: {}) has been deleted by admin [{}]", userToDelete.getUsername(), userToDelete.getId(), adminUsername);
    }
}
