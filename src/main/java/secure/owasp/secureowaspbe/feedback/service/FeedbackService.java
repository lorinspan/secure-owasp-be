package secure.owasp.secureowaspbe.feedback.service;

import lombok.RequiredArgsConstructor;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import secure.owasp.secureowaspbe.feedback.model.Feedback;
import secure.owasp.secureowaspbe.feedback.repository.FeedbackRepository;

import java.util.List;

@Service
@RequiredArgsConstructor
public class FeedbackService {

    private static final Logger logger = LoggerFactory.getLogger(FeedbackService.class);
    private final FeedbackRepository feedbackRepository;

    @Transactional
    public Feedback submitFeedback(String username, String message) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String loggedInUser = (auth != null && StringUtils.hasLength(auth.getName())) ? auth.getName() : "anonymousUser";

        if (loggedInUser.equals(username)) {
            logger.info("User [{}] is submitting feedback", loggedInUser);
        } else {
            logger.warn("User [{}] is submitting feedback as [{}]", loggedInUser, username);
        }

        if (!StringUtils.hasLength(message)) {
            throw new IllegalArgumentException("Feedback message cannot be empty.");
        }

        String sanitizedMessage = Jsoup.clean(message, Safelist.none());

        Feedback feedback = new Feedback();
        feedback.setUsername(username);
        feedback.setMessage(sanitizedMessage);

        Feedback savedFeedback = feedbackRepository.save(feedback);
        logger.info("User [{}] successfully submitted feedback.", username);
        return savedFeedback;
    }


    public List<Feedback> getAllFeedback() {
        return feedbackRepository.findAllByOrderByCreatedAtDesc();
    }
}
