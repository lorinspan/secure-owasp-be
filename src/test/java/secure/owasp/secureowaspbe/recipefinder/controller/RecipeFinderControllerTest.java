package secure.owasp.secureowaspbe.recipefinder.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.OK;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;
import secure.owasp.secureowaspbe.recipefinder.service.RecipeFinderService;

import java.util.List;
import java.util.Map;

public class RecipeFinderControllerTest {

    @InjectMocks
    private RecipeFinderController recipeFinderController;

    @Mock
    private RecipeFinderService recipeFinderService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void readRecipe_ValidFile_ReturnsContent() throws Exception {
        String filename = "validRecipe.txt";
        when(recipeFinderService.readRecipeFile(filename)).thenReturn("Recipe content");

        ResponseEntity<?> response = recipeFinderController.readRecipe(Map.of("filename", filename));

        assertEquals(OK, response.getStatusCode());
        assertEquals("Recipe content", ((Map<?, ?>) response.getBody()).get("content"));
    }

    @Test
    void readRecipe_InvalidPath_ThrowsSecurityException() throws Exception {
        String filename = "../secret.txt";
        when(recipeFinderService.readRecipeFile(filename)).thenThrow(new SecurityException("Access Denied"));

        ResponseEntity<?> response = recipeFinderController.readRecipe(Map.of("filename", filename));

        assertEquals(FORBIDDEN, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("Access Denied"));
    }

    @Test
    void listRecipes_ReturnsRecipeList() throws Exception {
        List<String> mockRecipes = List.of("recipe1.txt", "recipe2.txt");
        when(recipeFinderService.getAvailableRecipes()).thenReturn(mockRecipes);

        ResponseEntity<?> response = recipeFinderController.listRecipes();

        assertEquals(OK, response.getStatusCode());
        assertEquals(mockRecipes, ((Map<?, ?>) response.getBody()).get("recipes"));
    }
}
