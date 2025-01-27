### Token-based authentication in a REST API
**Work-in-progress study project**

This project does not use Spring Security, as that would defeat my purpose of learning about the inner workings of token authentication!

1. A user registers with username and password at a RegistrationService.
2. The HashService hashes the password with a random **salt** and a fixed **pepper** using the HMAC256 algorithm.
3. The username and the resulting digest are stored in a database (simulated here by UsernameSaltAndHashMap).


1. The user receives a **Refreshtoken** and **Accesstoken** by logging in with username and password at the /login endpoint (see AuthenticationController).
2. The Refreshtoken is saved in the database (simulated here by UsernameTokenMap)
2. The user can access a secured resource by supplying a valid Accesstoken (see SecuredResourceController)


1. When the Accesstoken is **invalid** (expired, or signature check fails) the user can get a new Accesstoken by supplying a valid Refreshtoken.
2. When the Refreshtoken is invalid the user must log in again.

### To do
* enable invalidation of refreshTokens and follow up on attempted use of an invalid refreshToken (see AuthenticationController).

