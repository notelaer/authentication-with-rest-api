package nl.bartnotelaers.authentication.service;

import nl.bartnotelaers.authentication.repository.UsernameSaltAndHashDatabase;
import nl.bartnotelaers.authentication.repository.UsernameTokenDatabase;
import nl.bartnotelaers.authentication.util.hash.SaltAndHash;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class AuthenticationService {
    private HashService hashService;
    private UsernameSaltAndHashDatabase usernameSaltAndHashDatabase;
    private UsernameTokenDatabase usernameTokenDatabase;


    public AuthenticationService(HashService hashService,
                                 UsernameSaltAndHashDatabase usernameSaltAndHashDatabase,
                                 UsernameTokenDatabase usernameTokenDatabase) {
        this.hashService = hashService;
        this.usernameSaltAndHashDatabase = usernameSaltAndHashDatabase;
        this.usernameTokenDatabase = usernameTokenDatabase;
    }

    public boolean authenticate(String username, String password) {
        SaltAndHash retrievedSaltHash = usernameSaltAndHashDatabase.getSaltAndHashByUsername(username);
        if (retrievedSaltHash != null ) {
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

    public boolean authenticate(String token) {
        // TODO check if JWT has correct format
        try {
            UUID uuidToken = UUID.fromString(token);
            return usernameTokenDatabase.hasToken(token);
        } catch (Exception e) {
            // instead of proper exception handling ( not the focus of this project)
            System.err.println("Invalid Token");
            return false;
        }
    }
}
