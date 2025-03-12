package secure.owasp.secureowaspbe.authentication.user.model;

import lombok.Getter;

@Getter
public class UserWithToken {
    private final User user;
    private final String token;

    public UserWithToken(User user, String token) {
        this.user = user;
        this.token = token;
    }
}