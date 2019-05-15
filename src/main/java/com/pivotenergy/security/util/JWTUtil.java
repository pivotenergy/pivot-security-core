package com.pivotenergy.security.util;

import com.pivotenergy.security.JWTSecurityService;
import org.springframework.http.HttpHeaders;

import javax.servlet.http.HttpServletRequest;

import static com.pivotenergy.security.JWTSecurityService.AUTHORIZATION_HEADER;
import static com.pivotenergy.security.JWTSecurityService.AUTHORIZATION_PREFIX_BEARER;

public class JWTUtil {

    public static String replacePrefix(String token, String prefix) {
        return token.replace(prefix,"").trim();
    }

    public static String getJwtHeader(HttpServletRequest request) {
        String accessToken = null;
        if(null != request) {
            if (null != request.getHeader(HttpHeaders.AUTHORIZATION) &&
                    request.getHeader(HttpHeaders.AUTHORIZATION).contains(AUTHORIZATION_PREFIX_BEARER)) {
                accessToken = request.getHeader(HttpHeaders.AUTHORIZATION);
            } else if (null != request.getHeader(AUTHORIZATION_HEADER) &&
                    request.getHeader(AUTHORIZATION_HEADER).contains(AUTHORIZATION_PREFIX_BEARER)) {
                accessToken = request.getHeader(AUTHORIZATION_HEADER);
            }
        }

        return accessToken;
    }

    public static String getOboHeader(HttpServletRequest request) {
        if (null != request.getHeader(JWTSecurityService.AUTHORIZATION_OBO)){
            return request.getHeader(JWTSecurityService.AUTHORIZATION_OBO);
        }

        return null;
    }
}
