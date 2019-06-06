package com.pivotenergy.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private static final String[] UNAUTHENTICATED = {"/actuator/**", "/refresh/**", "/logout/**", "/login/**",
            "/accounts/refresh/**", "/accounts/logout/**", "/accounts/login/**","/*.html", "/**/js/**", "/**/css/**",
            "/**/fonts/**", "/**/swagger-*/**", "/**/webjars/**", "/**/v2/api-docs/**"};

    @Override
    public void configure(WebSecurity web) {
        web.debug(false)
                .ignoring()
                .antMatchers(HttpMethod.HEAD)
                .antMatchers(HttpMethod.OPTIONS)
                .antMatchers(UNAUTHENTICATED);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        http
                .csrf().disable()
                // make sure we use stateless session; session won't be used to store user's state.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // Add a filter to validate the tokens with every request
                .addFilterBefore(new JWTAuthorizationFilter(jwtSecurityService()), BasicAuthenticationFilter.class)
                // authorization requests config
                .authorizeRequests()
                // allow all who are accessing "auth" service
                .antMatchers(UNAUTHENTICATED).permitAll()
                // Any other request must be authenticated
                .anyRequest().authenticated();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JWTSecurityService jwtSecurityService() {
        return new JWTSecurityService();
    }

    @Bean
    public JWTAuthorizationFilter jwtAuthorizationFilter() {
        return new JWTAuthorizationFilter(jwtSecurityService());
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl r = new RoleHierarchyImpl();
        StringBuilder builder = new StringBuilder();

        /*
         * Actions
         */
        builder.append("ROLE_ADMIN_ADMIN_GLOBAL > ROLE_ADMIN_CREATE_GLOBAL > ROLE_ADMIN_HARD_DELETE_GLOBAL > ");
        builder.append("ROLE_ADMIN_UPDATE_GLOBAL > ROLE_ADMIN_SOFT_DELETE_GLOBAL > ROLE_ADMIN_READ_GLOBAL and ");

        /*
         * Scopes
         */
        builder.append("ROLE_ADMIN_ADMIN_GLOBAL > ROLE_SUPPORT_ADMIN_GLOBAL > ");
        builder.append("ROLE_API_ADMIN_GLOBAL > ROLE_DEVELOPER_ADMIN_GLOBAL > ROLE_USER_ADMIN_GLOBAL and ");

        builder.append("ROLE_ADMIN_CREATE_GLOBAL > ROLE_ADMIN_CREATE_USERS and ");
        builder.append("ROLE_ADMIN_CREATE_GLOBAL > ROLE_ADMIN_CREATE_BUILDINGS and ");
        builder.append("ROLE_ADMIN_CREATE_BUILDINGS > ROLE_ADMIN_CREATE_BASELINES and ");
        builder.append("ROLE_ADMIN_CREATE_BUILDINGS > ROLE_ADMIN_CREATE_MEASURABLES and ");
        builder.append("ROLE_ADMIN_CREATE_BUILDINGS > ROLE_ADMIN_CREATE_OPPORTUNITIES > ROLE_ADMIN_CREATE_MEASURES and ");

        /*
         * GLOBAL targets
         */
        builder.append("ROLE_ADMIN_CREATE_GLOBAL > ROLE_SUPPORT_CREATE_GLOBAL > ");
        builder.append("ROLE_API_CREATE_GLOBAL > ROLE_DEVELOPER_CREATE_GLOBAL > ROLE_USER_CREATE_GLOBAL and ");
        builder.append("ROLE_ADMIN_HARD_DELETE_GLOBAL > ROLE_SUPPORT_HARD_DELETE_GLOBAL > ");
        builder.append("ROLE_API_HARD_DELETE_GLOBAL > ROLE_DEVELOPER_HARD_DELETE_GLOBAL > ROLE_USER_HARD_DELETE_GLOBAL and ");
        builder.append("ROLE_ADMIN_UPDATE_GLOBAL > ROLE_SUPPORT_UPDATE_GLOBAL > ");
        builder.append("ROLE_API_UPDATE_GLOBAL > ROLE_DEVELOPER_UPDATE_GLOBAL > ROLE_USER_UPDATE_GLOBAL and ");
        builder.append("ROLE_ADMIN_SOFT_DELETE_GLOBAL > ROLE_SUPPORT_SOFT_DELETE_GLOBAL > ");
        builder.append("ROLE_API_SOFT_DELETE_GLOBAL > ROLE_DEVELOPER_SOFT_DELETE_GLOBAL > ROLE_USER_SOFT_DELETE_GLOBAL and ");
        builder.append("ROLE_ADMIN_READ_GLOBAL > ROLE_SUPPORT_READ_GLOBAL > ");
        builder.append("ROLE_API_READ_GLOBAL > ROLE_DEVELOPER_READ_GLOBAL > ROLE_USER_READ_GLOBAL and ");

        /*
         * USERS targets
         */
        builder.append("ROLE_ADMIN_CREATE_USERS > ROLE_SUPPORT_CREATE_USERS > ");
        builder.append("ROLE_API_CREATE_USERS > ROLE_DEVELOPER_CREATE_USERS > ROLE_USER_CREATE_USERS and ");
        builder.append("ROLE_ADMIN_HARD_DELETE_USERS > ROLE_SUPPORT_HARD_DELETE_USERS > ");
        builder.append("ROLE_API_HARD_DELETE_USERS > ROLE_DEVELOPER_HARD_DELETE_USERS > ROLE_USER_HARD_DELETE_USERS and ");
        builder.append("ROLE_ADMIN_UPDATE_USERS > ROLE_SUPPORT_UPDATE_USERS > ");
        builder.append("ROLE_API_UPDATE_USERS > ROLE_DEVELOPER_UPDATE_USERS > ROLE_USER_UPDATE_USERS and ");
        builder.append("ROLE_ADMIN_SOFT_DELETE_USERS > ROLE_SUPPORT_SOFT_DELETE_USERS > ");
        builder.append("ROLE_API_SOFT_DELETE_USERS > ROLE_DEVELOPER_SOFT_DELETE_USERS > ROLE_USER_SOFT_DELETE_USERS and ");
        builder.append("ROLE_ADMIN_READ_USERS > ROLE_SUPPORT_READ_USERS > ");
        builder.append("ROLE_API_READ_USERS > ROLE_DEVELOPER_READ_USERS > ROLE_USER_READ_USERS and ");

        /*
         * BUILDINGS targets
         */
        builder.append("ROLE_ADMIN_CREATE_BUILDINGS > ROLE_SUPPORT_CREATE_BUILDINGS > ");
        builder.append("ROLE_API_CREATE_BUILDINGS > ROLE_DEVELOPER_CREATE_BUILDINGS > ROLE_USER_CREATE_BUILDINGS and ");
        builder.append("ROLE_ADMIN_HARD_DELETE_BUILDINGS > ROLE_SUPPORT_HARD_DELETE_BUILDINGS > ");
        builder.append("ROLE_API_HARD_DELETE_BUILDINGS > ROLE_DEVELOPER_HARD_DELETE_BUILDINGS > ROLE_USER_HARD_DELETE_BUILDINGS and ");
        builder.append("ROLE_ADMIN_UPDATE_BUILDINGS > ROLE_SUPPORT_UPDATE_BUILDINGS > ");
        builder.append("ROLE_API_UPDATE_BUILDINGS > ROLE_DEVELOPER_UPDATE_BUILDINGS > ROLE_USER_UPDATE_BUILDINGS and ");
        builder.append("ROLE_ADMIN_SOFT_DELETE_BUILDINGS > ROLE_SUPPORT_SOFT_DELETE_BUILDINGS > ");
        builder.append("ROLE_API_SOFT_DELETE_BUILDINGS > ROLE_DEVELOPER_SOFT_DELETE_BUILDINGS > ROLE_USER_SOFT_DELETE_BUILDINGS and ");
        builder.append("ROLE_ADMIN_READ_BUILDINGS > ROLE_SUPPORT_READ_BUILDINGS > ");
        builder.append("ROLE_API_READ_BUILDINGS > ROLE_DEVELOPER_READ_BUILDINGS > ROLE_USER_READ_BUILDINGS and ");

        /*
         * MEASURABLES targets
         */
        builder.append("ROLE_ADMIN_CREATE_MEASURABLES > ROLE_SUPPORT_CREATE_MEASURABLES > ");
        builder.append("ROLE_API_CREATE_MEASURABLES > ROLE_DEVELOPER_CREATE_MEASURABLES > ROLE_USER_CREATE_MEASURABLES and ");
        builder.append("ROLE_ADMIN_HARD_DELETE_MEASURABLES > ROLE_SUPPORT_HARD_DELETE_MEASURABLES > ");
        builder.append("ROLE_API_HARD_DELETE_MEASURABLES > ROLE_DEVELOPER_HARD_DELETE_MEASURABLES > ROLE_USER_HARD_DELETE_MEASURABLES and ");
        builder.append("ROLE_ADMIN_UPDATE_MEASURABLES > ROLE_SUPPORT_UPDATE_MEASURABLES > ");
        builder.append("ROLE_API_UPDATE_MEASURABLES > ROLE_DEVELOPER_UPDATE_MEASURABLES > ROLE_USER_UPDATE_MEASURABLES and ");
        builder.append("ROLE_ADMIN_SOFT_DELETE_MEASURABLES > ROLE_SUPPORT_SOFT_DELETE_MEASURABLES > ");
        builder.append("ROLE_API_SOFT_DELETE_MEASURABLES > ROLE_DEVELOPER_SOFT_DELETE_MEASURABLES > ROLE_USER_SOFT_DELETE_MEASURABLES and ");
        builder.append("ROLE_ADMIN_READ_MEASURABLES > ROLE_SUPPORT_READ_MEASURABLES > ");
        builder.append("ROLE_API_READ_MEASURABLES > ROLE_DEVELOPER_READ_MEASURABLES > ROLE_USER_READ_MEASURABLES and ");

        /*
         * BASELINES targets
         */
        builder.append("ROLE_ADMIN_CREATE_BASELINES > ROLE_SUPPORT_CREATE_BASELINES > ");
        builder.append("ROLE_API_CREATE_BASELINES > ROLE_DEVELOPER_CREATE_BASELINES > ROLE_USER_CREATE_BASELINES and ");
        builder.append("ROLE_ADMIN_HARD_DELETE_BASELINES > ROLE_SUPPORT_HARD_DELETE_BASELINES > ");
        builder.append("ROLE_API_HARD_DELETE_BASELINES > ROLE_DEVELOPER_HARD_DELETE_BASELINES > ROLE_USER_HARD_DELETE_BASELINES and ");
        builder.append("ROLE_ADMIN_UPDATE_BASELINES > ROLE_SUPPORT_UPDATE_BASELINES > ");
        builder.append("ROLE_API_UPDATE_BASELINES > ROLE_DEVELOPER_UPDATE_BASELINES > ROLE_USER_UPDATE_BASELINES and ");
        builder.append("ROLE_ADMIN_SOFT_DELETE_BASELINES > ROLE_SUPPORT_SOFT_DELETE_BASELINES > ");
        builder.append("ROLE_API_SOFT_DELETE_BASELINES > ROLE_DEVELOPER_SOFT_DELETE_BASELINES > ROLE_USER_SOFT_DELETE_BASELINES and ");
        builder.append("ROLE_ADMIN_READ_BASELINES > ROLE_SUPPORT_READ_BASELINES > ");
        builder.append("ROLE_API_READ_BASELINES > ROLE_DEVELOPER_READ_BASELINES > ROLE_USER_READ_BASELINES and ");

        /*
         * OPPORTUNITIES targets
         */
        builder.append("ROLE_ADMIN_CREATE_OPPORTUNITIES > ROLE_SUPPORT_CREATE_OPPORTUNITIES > ");
        builder.append("ROLE_API_CREATE_OPPORTUNITIES > ROLE_DEVELOPER_CREATE_OPPORTUNITIES > ROLE_USER_CREATE_OPPORTUNITIES and ");
        builder.append("ROLE_ADMIN_HARD_DELETE_OPPORTUNITIES > ROLE_SUPPORT_HARD_DELETE_OPPORTUNITIES > ");
        builder.append("ROLE_API_HARD_DELETE_OPPORTUNITIES > ROLE_DEVELOPER_HARD_DELETE_OPPORTUNITIES > ROLE_USER_HARD_DELETE_OPPORTUNITIES and ");
        builder.append("ROLE_ADMIN_UPDATE_OPPORTUNITIES > ROLE_SUPPORT_UPDATE_OPPORTUNITIES > ");
        builder.append("ROLE_API_UPDATE_OPPORTUNITIES > ROLE_DEVELOPER_UPDATE_OPPORTUNITIES > ROLE_USER_UPDATE_OPPORTUNITIES and ");
        builder.append("ROLE_ADMIN_SOFT_DELETE_OPPORTUNITIES > ROLE_SUPPORT_SOFT_DELETE_OPPORTUNITIES > ");
        builder.append("ROLE_API_SOFT_DELETE_OPPORTUNITIES > ROLE_DEVELOPER_SOFT_DELETE_OPPORTUNITIES > ROLE_USER_SOFT_DELETE_OPPORTUNITIES and ");
        builder.append("ROLE_ADMIN_READ_OPPORTUNITIES > ROLE_SUPPORT_READ_OPPORTUNITIES > ");
        builder.append("ROLE_API_READ_OPPORTUNITIES > ROLE_DEVELOPER_READ_OPPORTUNITIES > ROLE_USER_READ_OPPORTUNITIES and ");

        /*
         * MEASURES targets
         */
        builder.append("ROLE_ADMIN_CREATE_MEASURES > ROLE_SUPPORT_CREATE_MEASURES > ");
        builder.append("ROLE_API_CREATE_MEASURES > ROLE_DEVELOPER_CREATE_MEASURES > ROLE_USER_CREATE_MEASURES and ");
        builder.append("ROLE_ADMIN_HARD_DELETE_MEASURES > ROLE_SUPPORT_HARD_DELETE_MEASURES > ");
        builder.append("ROLE_API_HARD_DELETE_MEASURES > ROLE_DEVELOPER_HARD_DELETE_MEASURES > ROLE_USER_HARD_DELETE_MEASURES and ");
        builder.append("ROLE_ADMIN_UPDATE_MEASURES > ROLE_SUPPORT_UPDATE_MEASURES > ");
        builder.append("ROLE_API_UPDATE_MEASURES > ROLE_DEVELOPER_UPDATE_MEASURES > ROLE_USER_UPDATE_MEASURES and ");
        builder.append("ROLE_ADMIN_SOFT_DELETE_MEASURES > ROLE_SUPPORT_SOFT_DELETE_MEASURES > ");
        builder.append("ROLE_API_SOFT_DELETE_MEASURES > ROLE_DEVELOPER_SOFT_DELETE_MEASURES > ROLE_USER_SOFT_DELETE_MEASURES and ");
        builder.append("ROLE_ADMIN_READ_MEASURES > ROLE_SUPPORT_READ_MEASURES > ");
        builder.append("ROLE_API_READ_MEASURES > ROLE_DEVELOPER_READ_MEASURES > ROLE_USER_READ_MEASURES");

        r.setHierarchy(builder.toString());
        return r;
    }
}
