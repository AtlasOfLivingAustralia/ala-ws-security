package au.org.ala.ws.security;

import com.auth0.jwt.interfaces.Claim;
import org.springframework.security.core.AuthenticatedPrincipal;

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Map;


public class AuthenticatedUser implements Principal, AuthenticatedPrincipal {

    String email;
    String userId;
    List<String> roles = Collections.emptyList();
    Map<String, Claim> attributes = Collections.emptyMap();
    String firstName;
    String lastName;

    public AuthenticatedUser(){}

    public AuthenticatedUser(String email, String userId, List<String> roles, Map<String, Claim> attributes, String firstName, String lastName) {
        this.email = email;
        this.userId = userId;
        this.roles = roles;
        this.attributes = attributes;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    @Override
    public String getName() {
        return email;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public Map<String, Claim> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, Claim> attributes) {
        this.attributes = attributes;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }
}