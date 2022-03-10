package au.org.ala.ws.security;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.RSAPublicKey;

public final class JwtUtils {

    static Logger log = LoggerFactory.getLogger(JwtUtils.class);

    private JwtUtils(){}

    public static boolean verify(RSAPublicKey publicKey, DecodedJWT jwt) throws SignatureVerificationException {

        Algorithm algorithm = null;

        switch (jwt.getAlgorithm()) {
            case "RS256":
                algorithm = Algorithm.RSA256(publicKey, null);
                break;
            case "RS512":
                algorithm = Algorithm.RSA512(publicKey, null);
                break;
            default:
                log.warn("unsupported JWT algorithm {}", jwt.getAlgorithm());
                return false;
        }

        algorithm.verify(jwt);
        return true;
    }
}
