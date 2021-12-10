package au.org.ala.ws.security;

import com.google.common.collect.Lists;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static au.org.ala.ws.security.AlaWebServiceAuthFilter.LEGACY_X_ALA_USER_ID_HEADER;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest(SecurityContextHolder.class)
public class AlaWebServiceAuthFilterTest {

    @InjectMocks
    AlaWebServiceAuthFilter alaWebServiceAuthFilter = new AlaWebServiceAuthFilter();

    JwtService jwtService;
    LegacyApiKeyService legacyApiKeyService;
    RestTemplate restTemplate;

    @Mock SecurityContext securityContext;

    AutoCloseable mocks;

    @Before
    public void setup() {
        jwtService = mock(JwtService.class);
        legacyApiKeyService = mock(LegacyApiKeyService.class);
        restTemplate = mock(RestTemplate.class);

        PowerMockito.mockStatic(SecurityContextHolder.class);

        alaWebServiceAuthFilter.legacyApiKeysEnabled = true;

        mocks = MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testValidJwt() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer a-valid-jwt");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        SecurityContextHolder.setContext(securityContext);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserId("123");

        when(SecurityContextHolder.getContext()).thenReturn(securityContext);
        when(jwtService.checkJWT(any()))
                .thenReturn(Optional.of(authenticatedUser));

        alaWebServiceAuthFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<PreAuthenticatedAuthenticationToken> argument = ArgumentCaptor.forClass(PreAuthenticatedAuthenticationToken.class);
        verify(securityContext).setAuthentication(argument.capture());

        assertNotNull(argument.getValue());
        assertTrue(argument.getValue().isAuthenticated());

        assertNotNull("123", ((AuthenticatedUser) argument.getValue().getPrincipal()).userId);
    }

    @Test
    public void testNonValidJwt() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer a-invalid-jwt");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        SecurityContextHolder.setContext(securityContext);

        when(SecurityContextHolder.getContext()).thenReturn(securityContext);
        when(jwtService.checkJWT(any()))
                .thenReturn(Optional.empty());

        alaWebServiceAuthFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<PreAuthenticatedAuthenticationToken> argument = ArgumentCaptor.forClass(PreAuthenticatedAuthenticationToken.class);
        verifyNoInteractions(securityContext);
    }

    @Test
    public void testValidApiKey() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("apiKey", "Valid API Key");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        SecurityContextHolder.setContext(securityContext);

        when(SecurityContextHolder.getContext()).thenReturn(securityContext);
        when(legacyApiKeyService.isValidKey(any()))
                .thenReturn(Optional.of(new AuthenticatedUser()));

        alaWebServiceAuthFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<PreAuthenticatedAuthenticationToken> argument = ArgumentCaptor.forClass(PreAuthenticatedAuthenticationToken.class);
        verify(securityContext).setAuthentication(argument.capture());

        PreAuthenticatedAuthenticationToken token = argument.getValue();
        assertNotNull(token);
    }

    @Test
    public void testValidApiKeyAndUserId() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("apiKey", "Valid API Key");
        request.addHeader(LEGACY_X_ALA_USER_ID_HEADER, "19");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        SecurityContextHolder.setContext(securityContext);

        AuthenticatedUser apiUser = new AuthenticatedUser();
        apiUser.setUserId("000000");
        AuthenticatedUser actualUser = new AuthenticatedUser();
        actualUser.setUserId("19");

        when(SecurityContextHolder.getContext()).thenReturn(securityContext);
        when(legacyApiKeyService.isValidKey(any()))
                .thenReturn(Optional.of(apiUser));
        when(legacyApiKeyService.lookupAuthUser(anyString(), anyBoolean()))
                .thenReturn(Optional.of(actualUser));

        alaWebServiceAuthFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<PreAuthenticatedAuthenticationToken> argument = ArgumentCaptor.forClass(PreAuthenticatedAuthenticationToken.class);
        verify(securityContext).setAuthentication(argument.capture());

        PreAuthenticatedAuthenticationToken token = argument.getValue();
        assertEquals("19", ((AuthenticatedUser) token.getPrincipal()).userId);
    }

    @Test
    public void testValidApiKeyAndUserIdParam() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("apiKey", "Valid API Key");
        request.addParameter(AlaWebServiceAuthFilter.USER_ID_REQUEST_PARAM, "19");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        SecurityContextHolder.setContext(securityContext);

        AuthenticatedUser apiUser = new AuthenticatedUser();
        apiUser.setUserId("000000");
        AuthenticatedUser actualUser = new AuthenticatedUser();
        actualUser.setUserId("19");

        when(SecurityContextHolder.getContext()).thenReturn(securityContext);
        when(legacyApiKeyService.isValidKey(any()))
                .thenReturn(Optional.of(apiUser));
        when(legacyApiKeyService.lookupAuthUser(anyString(), anyBoolean()))
                .thenReturn(Optional.of(actualUser));

        alaWebServiceAuthFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<PreAuthenticatedAuthenticationToken> argument = ArgumentCaptor.forClass(PreAuthenticatedAuthenticationToken.class);
        verify(securityContext).setAuthentication(argument.capture());

        PreAuthenticatedAuthenticationToken token = argument.getValue();
        assertEquals("19", ((AuthenticatedUser) token.getPrincipal()).userId);
    }

    @Test
    public void testValidApiKeyParamAndUserIdParam() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("apiKey", "Valid API Key");
        request.addParameter(AlaWebServiceAuthFilter.USER_ID_REQUEST_PARAM, "19");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        SecurityContextHolder.setContext(securityContext);

        AuthenticatedUser apiUser = new AuthenticatedUser();
        apiUser.setUserId("000000");
        AuthenticatedUser actualUser = new AuthenticatedUser();
        actualUser.setUserId("19");

        when(SecurityContextHolder.getContext()).thenReturn(securityContext);
        when(legacyApiKeyService.isValidKey(any()))
                .thenReturn(Optional.of(apiUser));
        when(legacyApiKeyService.lookupAuthUser(anyString(), anyBoolean()))
                .thenReturn(Optional.of(actualUser));

        alaWebServiceAuthFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<PreAuthenticatedAuthenticationToken> argument = ArgumentCaptor.forClass(PreAuthenticatedAuthenticationToken.class);
        verify(securityContext).setAuthentication(argument.capture());

        PreAuthenticatedAuthenticationToken token = argument.getValue();
        assertEquals("19", ((AuthenticatedUser) token.getPrincipal()).userId);
    }


    @Test
    public void testWhiteList() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("apiKey", "Valid API Key");
        request.addParameter(AlaWebServiceAuthFilter.USER_ID_REQUEST_PARAM, "19");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        SecurityContextHolder.setContext(securityContext);

        AuthenticatedUser apiUser = new AuthenticatedUser();
        apiUser.setUserId("000000");
        AuthenticatedUser actualUser = new AuthenticatedUser();
        actualUser.setUserId("19");

        when(SecurityContextHolder.getContext()).thenReturn(securityContext);
        when(legacyApiKeyService.isValidKey(any()))
                .thenReturn(Optional.of(apiUser));
        when(legacyApiKeyService.lookupAuthUser(anyString(), anyBoolean()))
                .thenReturn(Optional.of(actualUser));

        alaWebServiceAuthFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<PreAuthenticatedAuthenticationToken> argument = ArgumentCaptor.forClass(PreAuthenticatedAuthenticationToken.class);
        verify(securityContext).setAuthentication(argument.capture());

        PreAuthenticatedAuthenticationToken token = argument.getValue();
        assertEquals("19", ((AuthenticatedUser) token.getPrincipal()).userId);
    }

}

