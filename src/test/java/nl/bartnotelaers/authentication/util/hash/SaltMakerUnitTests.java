package nl.bartnotelaers.authentication.util.hash;

import org.junit.jupiter.api.Test;


public class SaltMakerUnitTests {

    @Test
    public void generateSaltTestCorrectLength() {
        String resultSaltDefaultLength = SaltMaker.generateSalt();
        String resultSaltSpecificLength = SaltMaker.generateSalt(16);

        assert (resultSaltDefaultLength.length() == 16);
        assert (resultSaltSpecificLength.length() == 32);
    }

    @Test
    public void generateSaltTestDuplicate() {
        String salt1 = SaltMaker.generateSalt();
        String salt2 = SaltMaker.generateSalt();

        assert (!salt1.equals(salt2));
    }
}
