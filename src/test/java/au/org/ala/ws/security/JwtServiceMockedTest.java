package au.org.ala.ws.security;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.FileUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.File;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAMultiPrimePrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

@RunWith(PowerMockRunner.class)
@PrepareForTest(JwtUtils.class)
public class JwtServiceMockedTest {

    @InjectMocks
    JwtService jwtService = new JwtService();

    @Before
    public void setup() throws Exception {
        jwtService.jwkUrl = JwtServiceTest.getJwkUrl().toString();
    }

    @Test
    public void testJWTVerifyFails() throws Exception {
        String generatedJWT = JwtServiceTest.generateTestJwt(false);
        PowerMockito.mockStatic(JwtUtils.class);
        given(JwtUtils.verify(any(), any())).willThrow(new SignatureVerificationException(null));
        Optional<AuthenticatedUser> o = jwtService.checkJWT("Bearer " + generatedJWT);
        assertFalse(o.isPresent());
    }

}
