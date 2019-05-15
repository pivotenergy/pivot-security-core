package com.pivotenergy.security.model.request;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.util.Assert;

@SuppressWarnings("unused")
public class RefreshToken {

    @JsonProperty("refresh_token")
    private final String refreshToken;

    @JsonCreator
    public RefreshToken(String refreshToken) {
        Assert.notNull(refreshToken, "refreshToken cannot be null");
        this.refreshToken = refreshToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

}
