package secure.owasp.secureowaspbe.authentication.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitingInterceptor implements HandlerInterceptor {

    private static final int MAX_REQUESTS = 5; // Maxim 5 cereri pe minut
    private static final long TIME_WINDOW = 60 * 1000L; // 60 secunde

    private final Map<String, RequestCounter> requestCounts = new ConcurrentHashMap<>();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
        String clientIp = request.getRemoteAddr();

        requestCounts.putIfAbsent(clientIp, new RequestCounter());

        RequestCounter counter = requestCounts.get(clientIp);
        synchronized (counter) {
            long now = Instant.now().toEpochMilli();
            if (now - counter.startTime > TIME_WINDOW) {
                counter.reset(now);
            }

            if (counter.count >= MAX_REQUESTS) {
                response.setStatus(429);
                response.getWriter().write("Too many requests. Please try again later.");
                return false;
            }

            counter.count++;
        }

        return true;
    }

    private static class RequestCounter {
        private int count = 0;
        private long startTime = Instant.now().toEpochMilli();

        private void reset(long newStartTime) {
            this.count = 1;
            this.startTime = newStartTime;
        }
    }
}
