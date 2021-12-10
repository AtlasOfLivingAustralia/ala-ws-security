package au.org.ala.ws.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestOperations;

import javax.inject.Inject;
import java.util.*;

/**
 * Service for validating legacy api keys provided by apikey app.
 */
@Service
public class LegacyApiKeyService {

    public Logger log = LoggerFactory.getLogger(LegacyApiKeyService.class);

    public static final String ROLE_LEGACY_APIKEY = "ROLE_LEGACY_APIKEY";

    public static final String API_KEYS_CACHE_NAME = "apiKeys";

    @Value("${spring.security.legacy.userdetails.url:}")
    protected String userDetailsUrl;

    @Value("${spring.security.legacy.apikey.serviceUrl}")
    String legacyApiKeyServiceUrl;

    @Inject
    protected RestOperations restTemplate;

    @Inject
    protected CacheManager cacheManager;

    /**
     * Use a webservice to validate a key
     *
     * @param keyToTest
     * @return True if API key checking is disabled, or the API key is valid, and false otherwise.
     */
    public Optional<AuthenticatedUser> isValidKey(String keyToTest) {

        if (Objects.isNull(keyToTest)) {
            return Optional.empty();
        }

        // caching manually managed via the cacheManager not using the @Cacheable annotation
        // the @Cacheable annotation only works when an external call is made to a method, for
        // an explanation see: https://stackoverflow.com/a/32999744
        Cache cache = cacheManager.getCache(API_KEYS_CACHE_NAME);
        Cache.ValueWrapper valueWrapper = cache.get(keyToTest);

        if (valueWrapper != null && (AuthenticatedUser) valueWrapper.get() != null) {
            return Optional.of((AuthenticatedUser) valueWrapper.get());
        }

        //check via a web service
        try {
            if (log.isDebugEnabled()) {
                log.debug("Checking api key: " + keyToTest);
            }
            String url = legacyApiKeyServiceUrl + keyToTest;
            Map<String, Object> response = restTemplate.getForObject(url, Map.class);
            boolean isValid = (Boolean) response.getOrDefault("valid", false);
            String userId = (String) response.get("userId");
            String email = (String) response.get("email");
            if (log.isDebugEnabled()) {
                log.debug("Checking api key: " + keyToTest + ", valid: " + isValid);
            }
            if (isValid) {
                AuthenticatedUser auth = new AuthenticatedUser();
                auth.setEmail(email);
                auth.setUserId(userId);
                cache.put(keyToTest, auth);
                return Optional.of(auth);
            }

        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        return Optional.empty();
    }

    /**
     * Use user details services to get user.
     *
     * @param userIdOrEmail
     * @param getRoles
     * @return
     */
    public Optional<AuthenticatedUser> lookupAuthUser(String userIdOrEmail, boolean getRoles) {
        Map<String, Object> userDetails = (Map<String, Object>) getUserDetails(userIdOrEmail);
        if (userDetails == null || userDetails.isEmpty()) {
            return Optional.empty();
        }

        String userId = (String) userDetails.getOrDefault("userid", null);
        boolean activated = (Boolean) userDetails.getOrDefault("activated", false);
        boolean locked = (Boolean) userDetails.getOrDefault("locked", true);
        String firstName = (String) userDetails.getOrDefault("firstName", "");
        String lastName = (String) userDetails.getOrDefault("lastName", "");
        String email = (String) userDetails.getOrDefault("email", "");

        List<String> userRoles = Collections.emptyList();
        if (getRoles) {
            userRoles = (List<String>) userDetails.getOrDefault("roles", Collections.emptyList());
        }

        if (email != null && activated && !locked) {
            return Optional.of(
                    new AuthenticatedUser(email, userId, userRoles, Collections.emptyMap(), firstName, lastName)
            );
        } else {
            log.info("Download request with API key failed " +
                    "- email  " + email +
                    " , activated " + activated +
                    " , locked " + locked);
        }
        return Optional.empty();
    }

    /**
     * Lookup user details using the UserDetails web service API.
     * @param userId
     * @return
     */
    private Map<String,?> getUserDetails(String userId) {
        Map<String,?> userDetails = new HashMap<>();
        if (!Objects.isNull(userDetailsUrl) && !userDetailsUrl.isEmpty()){
            final String jsonUri = userDetailsUrl +  "/getUserDetails?userName=" + userId;
            log.info("authCache requesting: " + jsonUri);
            userDetails = (Map) restTemplate.postForObject(jsonUri, null, Map.class);
        }
        return userDetails;
    }
}
