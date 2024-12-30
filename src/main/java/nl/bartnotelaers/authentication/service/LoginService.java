package nl.bartnotelaers.authentication.service;

import nl.bartnotelaers.authentication.repository.UsernameTokenDatabase;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class LoginService {
    private final AuthenticationService authenticationService;
    private final UsernameTokenDatabase usernameTokenDatabase;

    public LoginService(AuthenticationService authenticationService,
                        UsernameTokenDatabase usernameTokenDatabase) {
        this.authenticationService = authenticationService;
        this.usernameTokenDatabase = usernameTokenDatabase;
    }

    public String login(String username, String password) {
        if (authenticationService.authenticate(username, password)) {
            // generate and return refresh token
            return authenticationService.createRefreshToken(username);
        } else {
            return null;
        }
    }
}
