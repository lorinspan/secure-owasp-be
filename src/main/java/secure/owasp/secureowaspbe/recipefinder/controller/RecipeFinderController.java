package secure.owasp.secureowaspbe.recipefinder.controller;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import secure.owasp.secureowaspbe.recipefinder.service.RecipeFinderService;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/recipes")
@RequiredArgsConstructor
public class RecipeFinderController {

    private static final Logger logger = LoggerFactory.getLogger(RecipeFinderController.class);
    private final RecipeFinderService recipeFinderService;

    @PostMapping("/read")
    public ResponseEntity<?> readRecipe(@RequestBody Map<String, String> request) {
        String requestedFile = request.get("filename");
        logger.info("Received request to read recipe file: {}", requestedFile);

        try {
            String content = recipeFinderService.readRecipeFile(requestedFile);
            logger.info("Successfully retrieved content for: {}", requestedFile);
            return ResponseEntity.ok(Map.of("content", content));

        } catch (SecurityException e) {
            logger.error("Security violation: {}", e.getMessage());
            return ResponseEntity.status(403).body(Map.of("error", e.getMessage()));

        } catch (Exception e) {
            logger.error("Error reading file: {}", e.getMessage());
            return ResponseEntity.status(500).body(Map.of("error", "Could not retrieve file."));
        }
    }

    @GetMapping("/list")
    public ResponseEntity<?> listRecipes() {
        logger.info("Received request to list available recipes.");

        try {
            List<String> recipes = recipeFinderService.getAvailableRecipes();
            return ResponseEntity.ok(Map.of("recipes", recipes));

        } catch (Exception e) {
            logger.error("Error retrieving recipe list: {}", e.getMessage());
            return ResponseEntity.status(500).body(Map.of("error", "Could not retrieve recipe list."));
        }
    }
}
