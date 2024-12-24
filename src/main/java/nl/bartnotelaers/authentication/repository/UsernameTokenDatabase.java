package nl.bartnotelaers.authentication.repository;

public interface UsernameTokenDatabase {
    public boolean insertToken(String username, String token);

    public boolean hasToken(String token);

}
