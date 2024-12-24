package nl.bartnotelaers.authentication.repository;

import nl.bartnotelaers.authentication.util.hash.SaltAndHash;

public interface UsernameSaltAndHashDatabase {
    public SaltAndHash getSaltAndHashByUsername(String username);

    public boolean insertUsernameSaltAndHash(String username, String salt, String hash);
}
