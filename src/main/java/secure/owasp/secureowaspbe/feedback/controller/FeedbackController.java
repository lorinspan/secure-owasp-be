package secure.owasp.secureowaspbe.feedback.controller;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import secure.owasp.secureowaspbe.feedback.model.Feedback;
import secure.owasp.secureowaspbe.feedback.service.FeedbackService;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/feedback")
@RequiredArgsConstructor
public class FeedbackController {

    private static final Logger logger = LoggerFactory.getLogger(FeedbackController.class);
    private final FeedbackService feedbackService;

    @PostMapping("/submit")
    public ResponseEntity<?> submitFeedback(@RequestBody Map<String, String> request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String loggedInUser = auth.getName();
        String username = request.get("username");
        String message = request.get("message");

        logger.info("User {} is attempting to submit feedback", loggedInUser);

        try {
            Feedback feedback = feedbackService.submitFeedback(username, message);
            return ResponseEntity.ok(feedback);
        } catch (SecurityException e) {
            logger.error("Unauthorized attempt by {}: {}", loggedInUser, e.getMessage());
            return ResponseEntity.status(403).body("Unauthorized attempt!");
        } catch (IllegalArgumentException e) {
            logger.error("Invalid feedback input: {}", e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/all")
    public ResponseEntity<List<Feedback>> getAllFeedback() {
        logger.info("Fetching all feedback");
        return ResponseEntity.ok(feedbackService.getAllFeedback());
    }
}
