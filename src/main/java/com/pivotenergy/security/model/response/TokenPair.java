package com.pivotenergy.security.model.response;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

@SuppressWarnings("unused")
public class TokenPair {
    @JsonProperty("token_type")
    private String tokenType;
    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("expires_in_seconds")
    private int expiresIn;
    @JsonProperty("refresh_token")
    private String refreshToken;

    public TokenPair() {}

    public TokenPair(String accessToken, int expiresIn, String refreshToken) {
        this.tokenType = "Bearer";
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
        this.refreshToken = refreshToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    @JsonIgnore
    public String getBearerToken() {
        return String.format("%s %s", tokenType, accessToken);
    }
}
