package com.pivotenergy.security.model.request;

import org.springframework.util.Assert;

@SuppressWarnings("unused")
public class UserLogin {

    private final String email;

    private final String password;

    public UserLogin(String email, String password) {
        Assert.notNull(email, "email/username cannot be null");
        Assert.notNull(password, "password cannot be null");
        this.email = email;
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }
}
