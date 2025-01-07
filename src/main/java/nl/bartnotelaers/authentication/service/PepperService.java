package nl.bartnotelaers.authentication.service;

import org.springframework.stereotype.Service;

@Service
public class PepperService {
    private final String PEPPER = "APepperShouldBeSavedElsewhereLikeInAHardwareSecurityModule";
    public String getPepper() {
        return PEPPER;
    }
}
