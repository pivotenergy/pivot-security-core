package com.pivotenergy.security;

import com.pivotenergy.security.model.UserSession;
import com.pivotenergy.security.util.JWTUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;

public class JWTAuthorizationFilter extends GenericFilterBean {

    private static final Logger LOG = LoggerFactory.getLogger(JWTAuthorizationFilter.class);

    private JWTSecurityService jwtSecurityService;

    public JWTAuthorizationFilter(JWTSecurityService jwtSecurityService) {
        this.jwtSecurityService = jwtSecurityService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        try {
            String token = JWTUtil.getJwtHeader((HttpServletRequest) request);
            String obo = JWTUtil.getOboHeader((HttpServletRequest) request);
            LOG.debug("JWTAuthorizationFilter fired for: {}", ((HttpServletRequest) request).getRequestURI());
            if (!((HttpServletRequest) request).getRequestURI().contains("/refresh/")) {
                if ((null == getContext().getAuthentication()) ||
                        !getContext().getAuthentication().isAuthenticated() ||
                        (getContext().getAuthentication() instanceof AnonymousAuthenticationToken)) {

                    if (null != token) {
                        LOG.debug("Attempting to verify JWT");
                        if (jwtSecurityService.jwtVerified(token)) {
                            LOG.debug("JWT verified");
                            LOG.debug("Attempting to populate SecurityContextHolder from JWT");
                            JWTAuthentication authentication = jwtSecurityService.authenticationFromToken(token);
                            if (null != authentication && canActOnBehalfOf(authentication.getDetails())) {
                                LOG.debug("User can act an behalf of account {}", obo);
                                authentication.getDetails().setTenantId(obo);
                            }
                            getContext().setAuthentication(authentication);
                            LOG.debug("SecurityContextHolder populated from JWT {}", authentication);
                        } else {

                            LOG.debug("JWT Authenticated failed ");
                        }
                    }
                }
            }
        }
        catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }

        chain.doFilter(request, response);
    }

    private boolean canActOnBehalfOf(UserSession user) {
        return null != user && hasPrivilegedType(user.getType()) &&
                user.getRoles().stream().anyMatch(role -> hasPrivilegedRole(role.getScope()));

    }

    private boolean hasPrivilegedType(UserSession.Type type) {
        return null != type && (type.equals(UserSession.Type.ADMIN) ||
                type.equals(UserSession.Type.SUPPORT));
    }

    private boolean hasPrivilegedRole(UserSession.Role.Scope scope) {
        return null != scope && (scope.equals(UserSession.Role.Scope.ROLE_ADMIN) ||
                scope.equals(UserSession.Role.Scope.ROLE_SUPPORT));
    }
}
