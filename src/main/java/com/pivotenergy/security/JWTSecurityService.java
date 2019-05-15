package com.pivotenergy.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.pivotenergy.security.model.UserSession;
import com.pivotenergy.security.model.response.TokenPair;
import com.pivotenergy.security.util.JSON;
import com.pivotenergy.security.util.JWTUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@SuppressWarnings("WeakerAccess")
@Service
@Configuration
public class JWTSecurityService {
    private static final Logger LOG = LoggerFactory.getLogger(JWTSecurityService.class);
    public static final String USER_PROFILE_CLAIM = "profile";
    public static final String AUTHORIZATION_HEADER = "X-AUTH-TOKEN";
    public static final String AUTHORIZATION_REFRESH = "X-REFRESH-TOKEN";
    public static final String AUTHORIZATION_OBO = "X-AUTH-OBO";
    public static final String AUTHORIZATION_PREFIX_BEARER = "Bearer ";
    public static final String AUTHORIZATION_PREFIX_BASIC = "Basic ";

    @Value("${token.config.expirationTime:600}")
    private long tokenLifeSeconds;

    @Value("${token.config.secret:secret}")
    private String secret;

    public JWTSecurityService(){}

    public JWTSecurityService(String secret, long expiration) {
        this.secret = secret;
        tokenLifeSeconds = expiration;
    }

    @SuppressWarnings("unused")
    public String getUserId() {
        return getUserInfo().getId();
    }

    public UserSession getUserInfo() {
        return (UserSession) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    @SuppressWarnings("unused")
    public String getAccountId() {
        return getUserInfo().getAccountId();
    }

    @SuppressWarnings("unused")
    public long getTokenLifeSeconds() {
        return tokenLifeSeconds;
    }

    /**
     * We have made this filter responsible for creating access tokens too.
     * This way, we keep all functionality regarding JWTs in a single place.
     */
    public <T extends UserDetails> String generateAccessToken(T user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withClaim(USER_PROFILE_CLAIM, JSON.toJsonSafe(user))
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + tokenLifeSeconds * 1000))
                .sign(Algorithm.HMAC256(secret.getBytes()));
    }

    @SuppressWarnings("unused")
    public <T extends UserDetails> JWTCreator.Builder buildJWT(T user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withClaim(USER_PROFILE_CLAIM, JSON.toJsonSafe(user))
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + tokenLifeSeconds * 1000));
    }

    @SuppressWarnings("unused")
    public String signJWT(JWTCreator.Builder jwt) {
        return jwt.sign(Algorithm.HMAC256(secret.getBytes()));
    }

    public boolean jwtVerified(String token) {
        boolean verified = false;

        if(null != token) {
            String webToken = JWTUtil.replacePrefix(token, AUTHORIZATION_PREFIX_BEARER);
            LOG.debug("jwtVerified: Cleansed JWT {}", webToken);
            try {
                JWT.require(Algorithm.HMAC256(secret.getBytes()))
                        .build()
                        .verify(webToken);

                verified = true;
            } catch (Exception e) {
                LOG.error(e.getMessage(), e);
            }
        }

        return verified;
    }

    public JWTAuthentication authenticationFromToken(String token) {
        JWTAuthentication authentication = null;

        if(null != token) {
            try {
                authentication = validateAuthenticationFromToken(token);
            } catch (Exception e) {
                LOG.error(e.getMessage(), e.getCause());
            }
        }

        return authentication;
    }

    public JWTAuthentication validateAuthenticationFromToken(String token) throws IOException {
        String webToken = JWTUtil.replacePrefix(token, AUTHORIZATION_PREFIX_BEARER);
        LOG.debug("Validating JWT");
        DecodedJWT jwt = JWT.require(Algorithm.HMAC256(secret.getBytes()))
                .build()
                .verify(webToken);
        LOG.debug("Validated JWT");
        LOG.debug("Creating JWTAuthentication");
        String refreshToken = jwt.getClaim(AUTHORIZATION_REFRESH).asString();
        Instant created = jwt.getIssuedAt().toInstant();
        Instant expires = jwt.getExpiresAt().toInstant();
        long expiresIn = Duration.between(created, expires).getSeconds();
        TokenPair tokenPair = new TokenPair(webToken, (int) expiresIn, refreshToken);
        UserSession user = JSON.fromJson(jwt.getClaim(USER_PROFILE_CLAIM).asString(), UserSession.class);
        LOG.debug("JWTAuthentication Created, returning");
        return new JWTAuthentication(user, webToken, user.getRoles()).setTokenPair(tokenPair);
    }
}
