package au.org.ala.ws.security;

import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class LegacyApiKeyServiceTest {

    @Spy
    CacheManager cacheManager = new ConcurrentMapCacheManager("apiKeys");

    AutoCloseable mocks;

    @InjectMocks
    LegacyApiKeyService legacyApiKeyService = new LegacyApiKeyService();

    RestTemplate restTemplate;

    @Before
    public void setup() {
        legacyApiKeyService.userDetailsUrl = "http://fake";
        restTemplate = mock(RestTemplate.class);
        mocks = MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testEmptyValidKey() throws Exception {

        Optional<AuthenticatedUser> authOptional = legacyApiKeyService.isValidKey(null);
        assertFalse(authOptional.isPresent());

        Optional<AuthenticatedUser> authOptional2 = legacyApiKeyService.isValidKey("");
        assertFalse(authOptional2.isPresent());
    }

    @Test
    public void testValidKey() throws Exception {

        Map<String, Object> response  = new HashMap<String, Object>() {{
            put("valid", Boolean.TRUE);
            put("email", "value1");
            put("userId", "value2");
        }};

        when(restTemplate.getForObject(any(String.class), any())).thenReturn(response);
        Optional<AuthenticatedUser> authOptional = legacyApiKeyService.isValidKey("valid-key");
        assertTrue(authOptional.isPresent());
    }

    @Test
    public void testInvalidKey() throws Exception {
        Map<String, Object> response  = new HashMap<String, Object>() {{
            put("valid", Boolean.FALSE);
        }};

        when(restTemplate.getForObject(any(String.class), any())).thenReturn(response);
        Optional<AuthenticatedUser> authOptional = legacyApiKeyService.isValidKey("invalid-key");
        assertTrue(!authOptional.isPresent());
    }

    @Test
    public void authValidEmailTestAllAttributes() {
        // mock the user details lookup
        when(restTemplate.postForObject(any(String.class), any(), any()))
                .thenReturn(new HashMap<String, Object>() {{
                    put("userid", "1234");
                    put("email", "test@test.com");
                    put("activated", true);
                    put("locked", false);
                    put("first_name", "Test");
                    put("last_name", "User");
                }});

        Optional<AuthenticatedUser> authenticatedUser =
                legacyApiKeyService.lookupAuthUser("1234", true);
        assertTrue(authenticatedUser.isPresent());
        assertEquals("1234", authenticatedUser.get().getUserId());
        assertEquals("test@test.com", authenticatedUser.get().getEmail());
    }

    @Test
    public void offlineDownloadValidEmailTestNoActivated() throws Exception {
        // mock the user details lookup
        when(restTemplate.postForObject(any(String.class), any(), any()))
                .thenReturn(new HashMap<String, Object>() {{
                    put("userid", "1234");
                    put("email", "test@test.com");
                    put("activated", false);
                    put("locked", false);
                    put("first_name", "Test");
                    put("last_name", "User");
                }});

        Optional<AuthenticatedUser> authenticatedUser =
                legacyApiKeyService.lookupAuthUser("1234", true);

        assertFalse(authenticatedUser.isPresent());
    }

    @Test
    public void offlineDownloadValidEmailTestLocked() throws Exception {
        // mock the user details lookup
        when(restTemplate.postForObject(any(String.class), any(), any()))
                .thenReturn(new HashMap<String, Object>() {{
                    put("userid", "1234");
                    put("email", "test@test.com");
                    put("activated", true);
                    put("locked", true);
                    put("first_name", "Test");
                    put("last_name", "User");
                }});

        Optional<AuthenticatedUser> authenticatedUser =
                legacyApiKeyService.lookupAuthUser("1234", true);

        assertFalse(authenticatedUser.isPresent());
    }

    @Test
    public void offlineDownloadInValidUserid() throws Exception {
        // mock the user details lookup
        when(restTemplate.postForObject(any(String.class), any(), any()))
                .thenReturn(new HashMap<String, Object>() {{ }});

        Optional<AuthenticatedUser> authenticatedUser =
                legacyApiKeyService.lookupAuthUser("1234", true);

        assertFalse(authenticatedUser.isPresent());
    }
}

