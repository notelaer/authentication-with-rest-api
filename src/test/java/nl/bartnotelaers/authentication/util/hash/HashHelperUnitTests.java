package nl.bartnotelaers.authentication.util.hash;

import org.junit.jupiter.api.Test;

public class HashHelperUnitTests {
    // hashed with SHA-256 using this online tool;
    // https://emn178.github.io/online-tools/sha256.html
    private final String password1 = "secretpassword";
    private final String password1hash = "95d30169a59c418b52013315fc81bc99fdf0a7b03a116f346ab628496f349ed5";
    private final String password2 = "mykittyissoSWEET!";
    private final String password2hash = "45c355ee54b103267a11d075a1058840620f334b47ff8811fc6dd21424c92663";
    private final String password3 = "loveCatVideos1992";
    private final String password3hash = "904048a0a594c813a3cddbf35f89c4d532287adef6c87463037278f5af7a524a";

    @Test
    public void hashTestSHA256() {
        String hashResult1 = HashHelper.hash(password1);
        String hashResult2 = HashHelper.hash(password2);
        String hashResult3 = HashHelper.hash(password3);
        assert (password1hash.equals(hashResult1));
        assert (password2hash.equals(hashResult2));
        assert (password3hash.equals(hashResult3));
    }
}

