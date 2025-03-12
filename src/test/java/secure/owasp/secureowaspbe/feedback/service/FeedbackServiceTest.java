package secure.owasp.secureowaspbe.feedback.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import secure.owasp.secureowaspbe.feedback.model.Feedback;
import secure.owasp.secureowaspbe.feedback.repository.FeedbackRepository;

public class FeedbackServiceTest {

    @InjectMocks
    private FeedbackService feedbackService;

    @Mock
    private FeedbackRepository feedbackRepository;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void submitFeedback_Success() {
        Feedback mockFeedback = new Feedback();
        mockFeedback.setUsername("user123");
        mockFeedback.setMessage("Great service!");

        when(feedbackRepository.save(any(Feedback.class))).thenReturn(mockFeedback);

        Feedback result = feedbackService.submitFeedback("user123", "Great service!");

        assertEquals("user123", result.getUsername());
        assertEquals("Great service!", result.getMessage());
    }

    @Test
    void submitFeedback_EmptyMessage() {
        assertThrows(IllegalArgumentException.class, () -> feedbackService.submitFeedback("user123", ""));
    }
}
