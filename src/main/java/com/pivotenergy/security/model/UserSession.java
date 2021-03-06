package com.pivotenergy.security.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserSession implements UserDetails {
    private String id;
    private String groupId;
    private String locale;
    private String userEmail;
    private String firstName;
    private String lastName;
    private Type type;
    private String tenantId;
    private Set<Role> roles = new HashSet<>();

    @Override
    @JsonIgnore
    public Set<GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(x -> new SimpleGrantedAuthority(x.getRole()))
                .collect(Collectors.toSet());
    }

    @Override
    @JsonIgnore
    public String getPassword() {
        return null;
    }

    @Override
    @JsonIgnore
    public String getUsername() {
        return userEmail;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return true;
    }

    @JsonIgnore
    public String getTenantId() {
        return Optional.ofNullable(tenantId).orElse(groupId);
    }

    @SuppressWarnings("unused")
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Role implements GrantedAuthority {
        private String role;
        private Scope scope;
        private Action action;
        private Target target;

        @Override
        public String getAuthority() {
            return role;
        }

        public Role addRole(Scope scope, Action action, Target target) {
            this.scope = scope;
            this.action = action;
            this.target = target;
            this.role = String.join("_", scope.toString(), action.toString(), target.toString());
            return this;
        }

        public enum Scope {
            ROLE_ADMIN,
            ROLE_SUPPORT,
            ROLE_API,
            ROLE_DEVELOPER,
            ROLE_USER
        }

        public enum Action {
            ADMIN,
            CREATE,
            SOFT_DELETE,
            HARD_DELETE,
            UPDATE,
            READ
        }

        public enum Target {
            GLOBAL,
            USERS,
            BUILDINGS,
            MEASURABLES,
            BASELINES,
            OPPORTUNITIES,
            MEASURES,
        }
    }

    @SuppressWarnings("unused")
    public enum Type {
        API,
        USER,
        ADMIN,
        SUPPORT
    }
}
