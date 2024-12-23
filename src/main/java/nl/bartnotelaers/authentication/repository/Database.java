package nl.bartnotelaers.authentication.repository;

import nl.bartnotelaers.authentication.util.hash.SaltAndHash;
import org.springframework.stereotype.Repository;

@Repository
public interface Database {
    public SaltAndHash findSaltAndHashByUsername(String username);

    public boolean insertUsernameSaltAndHash(String username, String salt, String hash);
}
