package nl.bartnotelaers.authentication.repository;

import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * a simple simulation of a database,
 * storing a username and its token
 **/
@Repository
public class UsernameTokenMap implements UsernameTokenDatabase {
    private Map<String, String> databaseMap; // username, token

    public UsernameTokenMap() {
        databaseMap = new ConcurrentHashMap<>();
    }

    public boolean insertToken(String username, String token) {
        // check if the username exists
        if (!databaseMap.containsKey(username)) {
            databaseMap.put(username, token);
            return true;
        } else {
            // instead of proper exception handling ( not the focus of this project)
            return false;
        }
    }

    public boolean hasToken(String token) {
        return databaseMap.containsValue(token);
    }

    public boolean check(String username, String token) {
        String retrievedValue = databaseMap.get(username);
        if (retrievedValue != null) {
            return retrievedValue.equals(token);
        } else {
            // instead of proper exception handling ( not the focus of this project)
            return false;
        }
    }
}
