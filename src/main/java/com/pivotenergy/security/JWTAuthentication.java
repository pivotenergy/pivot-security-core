package com.pivotenergy.security;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.pivotenergy.security.model.UserSession;
import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

/**
 * Represents all information, which has been extracted from JWT (currently only userId)
 */
@SuppressWarnings("WeakerAccess")
@JsonInclude(value = NON_NULL)
@Getter
public class JWTAuthentication extends UsernamePasswordAuthenticationToken {
    private String userId;
    private String groupId;
    private String tenantId;

    public JWTAuthentication(UserSession session) {
        super(session.getId(), session.getTenantId(), session.getAuthorities());
        super.setDetails(session);
        this.userId = session.getId();
        this.groupId = session.getGroupId();
        this.tenantId = session.getTenantId();
    }

    @Override
    public UserSession getDetails() {
        return (UserSession) super.getDetails();
    }

    @Override
    public String getPrincipal() {
        return (String) super.getPrincipal();
    }

    public String getUserId() {
        return userId;
    }

    public String getGroupId() {
        return groupId;
    }

    public String getTenantId() {
        return tenantId;
    }
}
