package nl.bartnotelaers.authentication.controller;

import nl.bartnotelaers.authentication.model.Credential;
import nl.bartnotelaers.authentication.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/authentication")
public class AuthenticationController {
    AuthenticationService authenticationService;

    @Autowired
    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    // validate user with username and password
    @GetMapping("/login")
    public ResponseEntity<?> validateUsernamePassword(@RequestBody Credential credential) {
        if (authenticationService.validateCredential(credential)) {
            String refreshToken = authenticationService.createRefreshToken(credential.getUsername());
            String accessToken = authenticationService.createAccessToken(credential.getUsername());
            String tokenJson = authenticationService.mapTokensToString(accessToken, refreshToken);
            return new ResponseEntity<>(tokenJson, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }

    // get a new access token by sending the refresh token in the header
    @PostMapping("/token")
    public ResponseEntity<?> getNewAccessToken(@RequestHeader("Authorization") String refreshToken) {
        if (authenticationService.validateAccessToken(refreshToken)) {
            String username = authenticationService.getUsernameFromToken(refreshToken);
            String newAccessToken = authenticationService.createAccessToken(username);
            return new ResponseEntity<>(newAccessToken, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }

    // get a new accessToken and refreshToken token by sending the refresh token in the header
    @PostMapping("/refresh")
    public ResponseEntity<?> getNewRefreshToken(@RequestHeader("Authorization") String refreshToken) {
        // TODO invalidate old refreshToken in database and follow up on use of invalidated refreshToken;
        // "If a refresh token is
        //  compromised and subsequently used by both the attacker and the
        //  legitimate client, one of them will present an invalidated refresh
        //  token, which will inform the authorization server of the breach."
        // https://www.rfc-editor.org/rfc/rfc6749#section-10.4
        if (authenticationService.validateRefreshToken(refreshToken)) {
            String username = authenticationService.getUsernameFromToken(refreshToken);
            String newRefreshToken = authenticationService.createRefreshToken(username);
            return new ResponseEntity<>(newRefreshToken, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }
}
