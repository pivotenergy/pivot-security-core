package com.pivotenergy.security.model.exceptions;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("unused")
public class JwtTokenMissingException extends AuthenticationException {

    public JwtTokenMissingException(String msg, Throwable t) {
        super(msg, t);
    }

    public JwtTokenMissingException(String msg) {
        super(msg);
    }
}
