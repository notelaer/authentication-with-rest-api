package nl.bartnotelaers.authentication.service;

import nl.bartnotelaers.authentication.repository.UsernameTokenDatabase;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.UUID;

@SpringBootTest
public class LoginServiceTests {
    LoginService loginService; // instance under test
    AuthenticationService authenticationService;
    UsernameTokenDatabase usernameTokenDatabase;
    RegistrationService registrationService;

    @Autowired
    public LoginServiceTests(LoginService loginService,
                             AuthenticationService authenticationService,
                             UsernameTokenDatabase usernameTokenDatabase,
                             RegistrationService registrationService) {
        this.loginService = loginService;
        this.authenticationService = authenticationService;
        this.usernameTokenDatabase = usernameTokenDatabase;
        this.registrationService = registrationService;
    }

    @Test
    public void loginSuccess() {
        registrationService.register("username", "password");
        String token = loginService.login("username", "password");
        try {
            UUID retrievedToken = UUID.fromString(token);
            assert (true);
        } catch (IllegalArgumentException e) {
            assert (false);
        }
    }

    @Test
    public void loginFail() {
        registrationService.register("username", "password");

        String token = loginService.login("wrong", "wrong");
        assert (token == null);
    }
}
