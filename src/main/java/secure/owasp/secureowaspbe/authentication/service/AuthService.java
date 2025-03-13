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
import secure.owasp.secureowaspbe.util.OwaspUtils;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public String login(String username, String password) {
        try {
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid username or password!"));

            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(username, password);

            authenticationManager.authenticate(authToken);
            return jwtUtil.generateToken(username, user.getRole());

        } catch (BadCredentialsException e) {
            throw new IllegalArgumentException("Invalid username or password!");
        }
    }

    public User register(User user) {
        logger.info("New user registration attempt: {}", user.getUsername());

        if (user.getUsername().length() < 5) {
            logger.warn("User [{}] attempted to register with a short username", user.getUsername());
            throw new IllegalArgumentException("Username must be at least 5 characters long!");
        }

        if (!Pattern.matches(OwaspUtils.EMAIL_PATTERN, user.getEmail())) {
            logger.warn("User [{}] attempted to register with an invalid email: {}", user.getUsername(), user.getEmail());
            throw new IllegalArgumentException("Invalid email format!");
        }

        if (!Pattern.matches(OwaspUtils.PASSWORD_PATTERN, user.getPassword())) {
            logger.warn("User [{}] attempted to register with a weak password", user.getUsername());
            throw new IllegalArgumentException("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character!");
        }

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
