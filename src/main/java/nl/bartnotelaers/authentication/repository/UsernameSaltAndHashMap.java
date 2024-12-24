package nl.bartnotelaers.authentication.repository;

import nl.bartnotelaers.authentication.util.hash.SaltAndHash;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * a simple simulation of a database,
 * storing a username and a hash (in this case, salt+password+pepper)
 **/
@Repository
public class UsernameSaltAndHashMap implements UsernameSaltAndHashDatabase {
    private Map<String, SaltAndHash> databaseMap; // username, SaltAndHash

    public UsernameSaltAndHashMap() {
        databaseMap = new ConcurrentHashMap<>();
    }

    public SaltAndHash getSaltAndHashByUsername(String username) {
        return databaseMap.get(username);
    }

    public boolean insertUsernameSaltAndHash(String username, String salt, String hash) {
        SaltAndHash saltAndHash = new SaltAndHash(salt, hash);
        // check if the username exists
        if (!databaseMap.containsKey(username)) {
            databaseMap.put(username, saltAndHash);
            return true;
        } else {
            // instead of proper exception handling ( not the focus of this project)
            return false;
        }
    }
}
