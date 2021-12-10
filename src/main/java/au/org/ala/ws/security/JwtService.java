package au.org.ala.ws.security;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static au.org.ala.ws.security.AlaWebServiceAuthFilter.BEARER;

@Service
public class JwtService {

    public Logger log = LoggerFactory.getLogger(JwtService.class);

    @Value("${spring.security.jwt.jwk.url}")
    String jwkUrl;

    /**
     * Verifies the signature of a JWT and retrieves the user information.
     *
     * @param authorizationHeader
     * @return
     */
    public Optional<AuthenticatedUser> checkJWT(String authorizationHeader) {

        try {
            if (!authorizationHeader.startsWith(BEARER)){
                return Optional.empty();
            }

            // https://auth0.com/docs/security/tokens/json-web-tokens/validate-json-web-tokens
            String token = authorizationHeader.substring(BEARER.length() + 1);

            // decode and verify
            DecodedJWT jwt = JWT.decode(token);
            JwkProvider provider = new UrlJwkProvider(new URL(jwkUrl));
            String keyId = jwt.getKeyId();
            Jwk jwk = provider.get(keyId);
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);

            try {
                algorithm.verify(jwt);
                // check the expiry....
                if (jwt.getExpiresAt().before(new Date())){
                    log.error("JWT expired");
                    return Optional.empty();
                }
                List<String> roles = jwt.getClaims().getOrDefault("role", new NullClaim()).asList(String.class);
                String email = jwt.getClaims().getOrDefault("email", new NullClaim()).asString();
                String userId = jwt.getClaims().getOrDefault("userid", new NullClaim()).asString();
                String firstName = jwt.getClaims().getOrDefault("given_name", new NullClaim()).asString();
                String lastName = jwt.getClaims().getOrDefault("family_name", new NullClaim()).asString();
                return Optional.of(new AuthenticatedUser(email, userId, roles, jwt.getClaims(), firstName, lastName));
            } catch (SignatureVerificationException e) {
                log.error("Verify of JWT failed");
                return Optional.empty();
            }
        } catch (JWTDecodeException e){
            // this will happen for some legacy API keys which are past in the Authorization header
            if (log.isDebugEnabled()) {
                log.debug("Decode of JWT failed, supplied authorizationHeader is not a recognised JWT");
                log.debug(e.getMessage(), e);
            }
        }  catch (Exception  e){
            if (log.isDebugEnabled()) {
                // this will happen for some legacy API keys which are past in the Authorization header
                log.debug("Check of JWT failed, supplied authorizationHeader is not a recognised JWT");
                log.debug(e.getMessage(), e);
            }
        }
        return Optional.empty();
    }
}
