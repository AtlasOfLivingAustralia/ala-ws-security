package au.org.ala.ws.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Converts a single Authority containing an attribute "authority" with a comma separated list of roles into
 * a Set of Authorities, one for each role.
 */
class AlaRoleMapper implements GrantedAuthoritiesMapper {

    public Logger log = LoggerFactory.getLogger(AlaRoleMapper.class);

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {

        Set<GrantedAuthority> roles = new HashSet();
        authorities.stream().forEach( it -> {
            if (it instanceof OAuth2UserAuthority) {
                mapOAuth2UserAuthority((OAuth2UserAuthority)it, roles);
            } else {
                log.warn("Mapper encountered an authority not of type OAuth2UserAuthority!");
                roles.add(it);
            }
        });
        return roles;
    }

    private void mapOAuth2UserAuthority(OAuth2UserAuthority authority, Set roles) {
        Object authorityAttribute = authority.getAttributes().get("authority");
        if (log.isDebugEnabled()) {
            log.debug("Mapping authority: ${authority.toString()} with authority ${authority.getAuthority()} with attribute: ${authorityAttribute}");
        }
        if (authorityAttribute != null && authorityAttribute instanceof String) {
            Arrays.stream(((String) authorityAttribute).split(",")).forEach( role ->
                    roles.add(new SimpleGrantedAuthority(role))
            );
        } else {
            log.warn("The OAuth2UserAuthority didn't have an authority attribute we could map.");
            roles.add(authority);
        }
    }
}
