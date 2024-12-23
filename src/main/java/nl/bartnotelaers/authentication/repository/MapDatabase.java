package nl.bartnotelaers.authentication.repository;

import nl.bartnotelaers.authentication.util.hash.SaltAndHash;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * a very simple simulation of a database,
 * used for storing a username and a hash (in this case, salt+password+pepper)
 **/
@Repository
public class MapDatabase implements Database {
    private Map<String, SaltAndHash> database;

    public MapDatabase() {
        database = new ConcurrentHashMap<>();
    }

    public SaltAndHash findSaltAndHashByUsername(String username) {
        return database.get(username);
    }

    public boolean insertUsernameSaltAndHash(String username, String salt, String hash) {
        SaltAndHash saltAndHash = new SaltAndHash(salt, hash);
        // check if the username exists
        if (!database.containsKey(username)) {
            database.put(username, saltAndHash);
            return true;
        }
        // instead of proper exception handling ( not the focus of this project)
        return false;
    }
}