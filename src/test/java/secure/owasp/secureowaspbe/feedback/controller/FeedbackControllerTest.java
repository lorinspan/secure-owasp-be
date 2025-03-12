package secure.owasp.secureowaspbe.feedback.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.OK;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import secure.owasp.secureowaspbe.feedback.model.Feedback;
import secure.owasp.secureowaspbe.feedback.service.FeedbackService;

import java.util.List;
import java.util.Map;

public class FeedbackControllerTest {

    @InjectMocks
    private FeedbackController feedbackController;

    @Mock
    private FeedbackService feedbackService;

    @Mock
    private Authentication authentication;

    @Mock
    private SecurityContext securityContext;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getName()).thenReturn("testUser");
        SecurityContextHolder.setContext(securityContext);
    }

    @Test
    void submitFeedback_Success() {
        String username = "testUser";
        String message = "This is a test feedback.";
        Feedback mockFeedback = new Feedback();
        mockFeedback.setUsername(username);
        mockFeedback.setMessage(message);

        when(feedbackService.submitFeedback(username, message)).thenReturn(mockFeedback);

        ResponseEntity<?> response = feedbackController.submitFeedback(Map.of("username", username, "message", message));

        assertEquals(OK, response.getStatusCode());
        assertEquals(mockFeedback, response.getBody());
    }

    @Test
    void submitFeedback_UnauthorizedAttempt() {
        String username = "anotherUser";
        String message = "This is a test feedback.";

        when(feedbackService.submitFeedback(username, message)).thenThrow(new SecurityException("Unauthorized"));

        ResponseEntity<?> response = feedbackController.submitFeedback(Map.of("username", username, "message", message));

        assertEquals(FORBIDDEN, response.getStatusCode());
        assertEquals("Unauthorized attempt!", response.getBody());
    }

    @Test
    void submitFeedback_InvalidInput() {
        String username = "testUser";
        String message = "";

        when(feedbackService.submitFeedback(username, message)).thenThrow(new IllegalArgumentException("Feedback message cannot be empty."));

        ResponseEntity<?> response = feedbackController.submitFeedback(Map.of("username", username, "message", message));

        assertEquals(BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("Feedback message cannot be empty."));
    }

    @Test
    void getAllFeedback_ReturnsList() {
        List<Feedback> mockFeedbackList = List.of(new Feedback(), new Feedback());
        when(feedbackService.getAllFeedback()).thenReturn(mockFeedbackList);

        ResponseEntity<List<Feedback>> response = feedbackController.getAllFeedback();

        assertEquals(OK, response.getStatusCode());
        assertEquals(mockFeedbackList, response.getBody());
    }
}
