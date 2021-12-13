package au.org.ala.ws.security;

import org.junit.Before;
import org.junit.Test;
import org.mockito.MockitoAnnotations;
import org.powermock.api.mockito.PowerMockito;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

public class AlaRoleMapperTest {

    @Before
    public void setup() {
    }

    @Test
    public void testNullMapping() throws Exception {
        AlaRoleMapper mapper = new AlaRoleMapper();
        Collection<? extends GrantedAuthority> mapped = mapper.mapAuthorities(null);
        assertNotNull(mapped);
        assertTrue(mapped.isEmpty());
    }

    @Test
    public void testEmptyMapping() throws Exception {
        AlaRoleMapper mapper = new AlaRoleMapper();
        Collection<? extends GrantedAuthority> mapped = mapper.mapAuthorities(Collections.EMPTY_LIST);
        assertNotNull(mapped);
        assertTrue(mapped.isEmpty());
    }

    @Test
    public void testNonEmptyMapping() throws Exception {
        AlaRoleMapper mapper = new AlaRoleMapper();
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));

        Collection<? extends GrantedAuthority> mapped = mapper.mapAuthorities(authorities);
        assertNotNull(mapped);
        assertFalse(mapped.isEmpty());
        assertEquals(1, mapped.size());
    }

    @Test
    public void testOAuth2Mapping() throws Exception {
        AlaRoleMapper mapper = new AlaRoleMapper();
        Collection<OAuth2UserAuthority> authorities = new ArrayList<>();
        authorities.add(new OAuth2UserAuthority(new HashMap<String, Object>(){{
            put("authority", "ROLE_ADMIN,ROLE_NUMBER2");
        }}));

        Collection<? extends GrantedAuthority> mapped = mapper.mapAuthorities(authorities);
        assertNotNull(mapped);
        assertFalse(mapped.isEmpty());
        assertEquals(2, mapped.size());
    }

//    @Test
//    public void testOIDCMapping() throws Exception {
//        AlaRoleMapper mapper = new AlaRoleMapper();
//        Collection<OAuth2UserAuthority> authorities = new ArrayList<>();
//        authorities.add(new OidcUserAuthority(new HashMap<String, Object>(){{
//            put("authority", "ROLE_ADMIN,ROLE_NUMBER2");
//        }}));
//
//        Collection<? extends GrantedAuthority> mapped = mapper.mapAuthorities(authorities);
//        assertNotNull(mapped);
//        assertFalse(mapped.isEmpty());
//        assertEquals(2, mapped.size());
//    }
}
