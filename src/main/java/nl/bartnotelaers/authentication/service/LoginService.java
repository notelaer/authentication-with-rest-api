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
            // TODO replace opaque token with JWT
            // generate opaque token
            String newToken = UUID.randomUUID().toString();
            // store token in database
            usernameTokenDatabase.insertToken(username, newToken);
            return newToken;
        } else {
            return null;
        }
    }
}
