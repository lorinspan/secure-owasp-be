package secure.owasp.secureowaspbe.recipefinder.service;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class RecipeFinderService {

    private static final Logger logger = LoggerFactory.getLogger(RecipeFinderService.class);
    private static final Path BASE_PATH = Paths.get("src/main/resources/recipes").toAbsolutePath().normalize();

    public String readRecipeFile(String requestedFile) throws IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = (auth != null && StringUtils.hasLength(auth.getName())) ? auth.getName() : "anonymousUser";;

        Path resolvedPath = BASE_PATH.resolve(requestedFile).normalize();

        if (!resolvedPath.startsWith(BASE_PATH)) {
            logger.warn("User [{}] attempted Path Traversal: {}", username, requestedFile);
            throw new SecurityException("Access Denied: Invalid file path.");
        }

        if (!Files.exists(resolvedPath) || !Files.isRegularFile(resolvedPath)) {
            logger.warn("User [{}] tried to access non-existing file: {}", username, requestedFile);
            throw new SecurityException("Access Denied: File does not exist.");
        }

        logger.info("User [{}] reading file: {}", username, resolvedPath);
        return Files.readString(resolvedPath);
    }

    public List<String> getAvailableRecipes() throws IOException {
        try (Stream<Path> paths = Files.list(BASE_PATH)) {
            return paths
                    .filter(Files::isRegularFile)
                    .map(path -> path.getFileName().toString())
                    .collect(Collectors.toList());
        } catch (IOException e) {
            logger.error("Error listing available recipes: {}", e.getMessage());
            throw new IOException("Could not list available recipes.");
        }
    }
}
