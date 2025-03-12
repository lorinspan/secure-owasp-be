package secure.owasp.secureowaspbe.recipefinder.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RecipeFinderServiceTest {

    private RecipeFinderService recipeFinderService;

    MockedStatic<SecurityContextHolder> mockedSecurityContextHolder;

    @BeforeEach
    void setUp() {
        recipeFinderService = new RecipeFinderService();

        mockedSecurityContextHolder = Mockito.mockStatic(SecurityContextHolder.class);
        SecurityContext securityContext = mock(SecurityContext.class);
        Authentication authentication = mock(Authentication.class);

        when(authentication.getName()).thenReturn("testUser");
        when(securityContext.getAuthentication()).thenReturn(authentication);
        mockedSecurityContextHolder.when(SecurityContextHolder::getContext).thenReturn(securityContext);
    }

    @AfterEach
    void after() {
        mockedSecurityContextHolder.close();
    }

    @Test
    void readRecipeFile_InvalidPath_ThrowsSecurityException() {
        assertThrows(SecurityException.class, () -> recipeFinderService.readRecipeFile("../secret.txt"));
    }

    @Test
    void readRecipeFile_NonExistingFile_ThrowsSecurityException() {
        Path mockPath = Path.of("src/main/resources/recipes/missing.txt");

        try (MockedStatic<Files> mockedFiles = Mockito.mockStatic(Files.class)) {
            mockedFiles.when(() -> Files.exists(mockPath)).thenReturn(false);

            assertThrows(SecurityException.class, () -> recipeFinderService.readRecipeFile("missing.txt"));
        }
    }
}
