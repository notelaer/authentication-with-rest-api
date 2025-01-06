package nl.bartnotelaers.authentication.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import nl.bartnotelaers.authentication.model.Credential;
import nl.bartnotelaers.authentication.repository.UsernameSaltAndHashDatabase;
import nl.bartnotelaers.authentication.repository.UsernameTokenDatabase;
import nl.bartnotelaers.authentication.util.hash.SaltAndHash;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Authenticate users based on username/password, access token or refresh token
 * could be set up on a separate authentication server
 */
@Service
public class AuthenticationService {
    private HashService hashService;
    private UsernameSaltAndHashDatabase usernameSaltAndHashDatabase;
    private UsernameTokenDatabase usernameTokenDatabase;

    // secret for encoding and decoding jwt is set in environment variables
    private final String SECRET = System.getenv("JWT_SECRET");
    // algorithm to use with encoding and decoding JWT
    private final Algorithm algorithm = Algorithm.HMAC256(SECRET);

    @Value("${authentication.accessTokenExpiration}")
    private int ACCESS_TOKEN_EXPIRATION;
    @Value("${authentication.refreshTokenExpiration}")
    private int REFRESH_TOKEN_EXPIRATION;

    public AuthenticationService(HashService hashService,
                                 UsernameSaltAndHashDatabase usernameSaltAndHashDatabase,
                                 UsernameTokenDatabase usernameTokenDatabase) {
        this.hashService = hashService;
        this.usernameSaltAndHashDatabase = usernameSaltAndHashDatabase;
        this.usernameTokenDatabase = usernameTokenDatabase;
    }

    public boolean validateCredential(Credential credential) {
        String username = credential.getUsername();
        SaltAndHash retrievedSaltHash = usernameSaltAndHashDatabase.getSaltAndHashByUsername(username);
        if (retrievedSaltHash != null) {
            String password = credential.getPassword();
            String givenHash = hashService.hash(retrievedSaltHash.getSalt(), password);
            String storedHash = retrievedSaltHash.getHash();
            if (givenHash.equals(storedHash)) {
                return true;
            } else {
                return false;
            }
        }
        return false;
    }

    // simple and insecure validation of a JWT's payload (without checking signature)
    // written as a stepping stone for learning about JWTs
    public boolean validateJwt(String jwt) {
        try {
            // split jwt into header, payload and signature
            String[] chunks = jwt.split("\\.");
            // decode payload
            Base64.Decoder decoder = Base64.getUrlDecoder();
            String payload = new String(decoder.decode(chunks[1]));
            // TODO either use decoded payload or DecodedJWT, not both :-)
            // get values for keys "username" and "token"
            DecodedJWT decodedJwt = JWT.require(algorithm)
                    .build()
                    .verify(jwt);
            String username = decodedJwt.getSubject();
            String token = decodedJwt.getClaim("token").asString();
            // check username and token in database
            return usernameTokenDatabase.check(username, token);
        } catch (Exception e) {
            // instead of proper exception handling ( not the focus of this project)
            return false;
        }
    }

    public String createAccessToken(String username) {
        Instant expiration = Instant.now().plusSeconds(ACCESS_TOKEN_EXPIRATION);
        return JWT.create()
                .withSubject(username)
                .withExpiresAt(expiration)
                .sign(algorithm);
    }

    // validate a JWT access token with DateTime claim check and signature check
    public boolean validateAccessToken(String token) {
        JWTVerifier verifier = JWT.require(algorithm).build();
        // validate jwt (includes DateTime claim validation)
        try {
            verifier.verify(token);
            return true;
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    // create refresh token (JWT with included access token)
    public String createRefreshToken(String username) {
        String refreshString = UUID.randomUUID().toString();
        usernameTokenDatabase.insertToken(username, refreshString);
        Instant expiration = Instant.now().plusSeconds(REFRESH_TOKEN_EXPIRATION);
        return JWT.create()
                .withSubject(username)
                .withClaim("refreshToken", refreshString)
                .withExpiresAt(expiration)
                .sign(algorithm);
    }

    // validate a refresh token with database check
    public boolean validateRefreshToken(String token) {
        try {
            // verify includes DateTime claim validation
            DecodedJWT decodedJwt = JWT.require(algorithm)
                    .build()
                    .verify(token);
            String username = decodedJwt.getSubject();
            String uuid = decodedJwt.getClaim("refreshToken").asString();
            return usernameTokenDatabase.check(username, uuid);
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        DecodedJWT decodedJwt = JWT.require(algorithm)
                .build()
                .verify(token);
        return decodedJwt.getSubject();
    }

    public String mapTokensToString(String accessToken, String refreshToken) {
        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put("accessToken", accessToken);
        tokenMap.put("refreshToken", refreshToken);
        return tokenMap.toString();
    }
}
