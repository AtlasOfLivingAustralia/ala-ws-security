package au.org.ala.ws.security;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.security.interfaces.RSAPublicKey;

public class JwtUtils {

    public static boolean verify(RSAPublicKey publicKey, DecodedJWT jwt) throws SignatureVerificationException {
        Algorithm algorithm = Algorithm.RSA256(publicKey, null);
        algorithm.verify(jwt);
        return true;
    }
}
