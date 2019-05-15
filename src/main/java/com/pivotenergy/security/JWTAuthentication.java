package com.pivotenergy.security;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.pivotenergy.security.model.UserSession;
import com.pivotenergy.security.model.response.TokenPair;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

/**
 * Represents all information, which has been extracted from JWT (currently only userId)
 */
@SuppressWarnings("WeakerAccess")
@JsonInclude(value = NON_NULL)
public class JWTAuthentication extends UsernamePasswordAuthenticationToken {

    public JWTAuthentication(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }

    public TokenPair getTokenPair() {
        return (TokenPair) super.getDetails();
    }

    @Override
    public UserSession getPrincipal() {
        return (UserSession) super.getPrincipal();
    }


    public JWTAuthentication setTokenPair(TokenPair tokenPair) {
        super.setDetails(tokenPair);
        return this;
    }
}
