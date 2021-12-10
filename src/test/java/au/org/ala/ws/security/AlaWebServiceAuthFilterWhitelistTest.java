package au.org.ala.ws.security;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Optional;

import static au.org.ala.ws.security.AlaWebServiceAuthFilter.LEGACY_X_ALA_USER_ID_HEADER;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest(SecurityContextHolder.class)
public class AlaWebServiceAuthFilterWhitelistTest {

    @InjectMocks
    AlaWebServiceAuthFilter alaWebServiceAuthFilter = new AlaWebServiceAuthFilter();

    LegacyApiKeyService legacyApiKeyService;

    @Mock SecurityContext securityContext;

    AutoCloseable mocks;

    @Before
    public void setup() {

        PowerMockito.mockStatic(SecurityContextHolder.class);

        alaWebServiceAuthFilter.jwtApiKeysEnabled = false;
        alaWebServiceAuthFilter.legacyApiKeysEnabled = false;
        alaWebServiceAuthFilter.whitelistEnabled = true;
        alaWebServiceAuthFilter.whitelistOfips = "123.123.123.123,123.123.123.124";
        mocks = MockitoAnnotations.openMocks(this);
    }


    @Test
    public void testWhiteList() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Forwarded-For", "123.123.123.123");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();


        SecurityContextHolder.setContext(securityContext);

        AuthenticatedUser apiUser = new AuthenticatedUser();
        apiUser.setUserId("000000");

        when(SecurityContextHolder.getContext()).thenReturn(securityContext);

        alaWebServiceAuthFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<PreAuthenticatedAuthenticationToken> argument = ArgumentCaptor.forClass(PreAuthenticatedAuthenticationToken.class);
        verify(securityContext).setAuthentication(argument.capture());

        PreAuthenticatedAuthenticationToken token = argument.getValue();

        List<String> roles = ((AuthenticatedUser) token.getPrincipal()).getRoles();

        assertEquals(1, roles.size());
        assertEquals(LegacyApiKeyService.ROLE_LEGACY_APIKEY, roles.get(0));
    }

    @Test
    public void testWhiteListRemoteHost() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteHost("123.123.123.123");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();


        SecurityContextHolder.setContext(securityContext);

        AuthenticatedUser apiUser = new AuthenticatedUser();
        apiUser.setUserId("000000");

        when(SecurityContextHolder.getContext()).thenReturn(securityContext);

        alaWebServiceAuthFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<PreAuthenticatedAuthenticationToken> argument = ArgumentCaptor.forClass(PreAuthenticatedAuthenticationToken.class);
        verify(securityContext).setAuthentication(argument.capture());

        PreAuthenticatedAuthenticationToken token = argument.getValue();

        List<String> roles = ((AuthenticatedUser) token.getPrincipal()).getRoles();

        assertEquals(1, roles.size());
        assertEquals(LegacyApiKeyService.ROLE_LEGACY_APIKEY, roles.get(0));
    }

    @Test
    public void testNotOnWhiteListRemoteHost() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteHost("123.123.123.999");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();


        SecurityContextHolder.setContext(securityContext);

        AuthenticatedUser apiUser = new AuthenticatedUser();
        apiUser.setUserId("000000");

        when(SecurityContextHolder.getContext()).thenReturn(securityContext);

        alaWebServiceAuthFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<PreAuthenticatedAuthenticationToken> argument = ArgumentCaptor.forClass(PreAuthenticatedAuthenticationToken.class);
        verifyNoInteractions(securityContext);
    }
}

