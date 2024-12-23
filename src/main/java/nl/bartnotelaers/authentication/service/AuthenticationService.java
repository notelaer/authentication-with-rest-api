package nl.bartnotelaers.authentication.service;

import nl.bartnotelaers.authentication.repository.Database;
import nl.bartnotelaers.authentication.util.hash.SaltAndHash;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    private final Database database;
    private final HashService hashService;

    @Autowired
    public AuthenticationService(Database database, HashService hashService) {
        this.database = database;
        this.hashService = hashService;
    }

    public boolean authenticate(String username, String password) {
        SaltAndHash retrievedSaltHash = database.findSaltAndHashByUsername(username);
        String givenHash = hashService.hash(retrievedSaltHash.getSalt(), password);
        String storedHash = retrievedSaltHash.getHash();
        if (givenHash.equals(storedHash)) {
            return true;
        } else {
            return false;
        }
    }
}
