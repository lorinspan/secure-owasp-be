package secure.owasp.secureowaspbe.authentication.service;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import secure.owasp.secureowaspbe.authentication.user.model.User;
import secure.owasp.secureowaspbe.authentication.user.repository.UserRepository;
import secure.owasp.secureowaspbe.security.jwt.JwtUtil;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    private static final Map<String, Integer> failedLoginAttempts = new ConcurrentHashMap<>();
    private static final int MAX_ATTEMPTS = 5;

    public String login(String username, String password) {
        if (isBlocked(username)) {
            throw new IllegalArgumentException("Too many failed attempts. Please try again later.");
        }

        try {
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid username or password!"));

            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(username, password);

            authenticationManager.authenticate(authToken);
            failedLoginAttempts.remove(username);
            return jwtUtil.generateToken(username, user.getRole());

        } catch (BadCredentialsException e) {
            increaseFailedAttempts(username);
            throw new IllegalArgumentException("Invalid username or password!");
        }
    }

    private void increaseFailedAttempts(String username) {
        int attempts = failedLoginAttempts.getOrDefault(username, 0) + 1;
        failedLoginAttempts.put(username, attempts);

        if (attempts == 1) {
            logger.warn("First failed login attempt for user [{}]", username);
        } else if (attempts == MAX_ATTEMPTS - 1) {
            logger.warn("User [{}] is about to be blocked! Attempts: {}/{}", username, attempts, MAX_ATTEMPTS);
        } else if (attempts >= MAX_ATTEMPTS) {
            logger.error("User [{}] is now blocked due to too many failed attempts!", username);
        }
    }

    private boolean isBlocked(String username) {
        return failedLoginAttempts.getOrDefault(username, 0) >= MAX_ATTEMPTS;
    }

    public User register(User user) {
        logger.info("New user registration attempt: {}", user.getUsername());

        if (userRepository.existsByUsername(user.getUsername())) {
            logger.warn("User [{}] attempted to register with an existing username", user.getUsername());
            throw new IllegalArgumentException("Username already exists!");
        }

        if (userRepository.existsByEmail(user.getEmail())) {
            logger.warn("User [{}] attempted to register with an existing email: {}", user.getUsername(), user.getEmail());
            throw new IllegalArgumentException("Email already exists!");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole("USER");

        User savedUser = userRepository.save(user);
        logger.info("New user registered successfully: [{}] (ID: {})", savedUser.getUsername(), savedUser.getId());
        return savedUser;
    }
}
