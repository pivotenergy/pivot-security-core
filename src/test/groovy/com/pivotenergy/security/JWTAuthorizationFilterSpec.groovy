package com.pivotenergy.security

import com.pivotenergy.security.model.UserSession
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.core.context.SecurityContextHolder
import spock.lang.Specification

class JWTAuthorizationFilterSpec extends Specification {
    def service = new JWTSecurityService("secret", 60)
    def filter = new JWTAuthorizationFilter(service)
    def mockRequest = new MockHttpServletRequest()
    def mockResponse = new MockHttpServletResponse()
    def mockFilterChain = new MockFilterChain()
    def authHeader = "X-AUTH-TOKEN"
    def jwt = service.generateAccessToken(initUserInfo())

    def setup() {
        SecurityContextHolder.clearContext()
    }

    def "security context should be null when request has not authentication header"() {
        when: "filter internal logic is run"
        filter.doFilter(mockRequest, mockResponse, mockFilterChain)

        then: "security context is null"
        SecurityContextHolder.getContext().getAuthentication() == null
    }

    def "security context should be null when header does not apply bearer schema"() {
        given: "request with invalid authorization header schema"
        mockRequest.addHeader("Authorization", "Invalid token header")

        when: "filter internal logic is run"
        filter.doFilter(mockRequest, mockResponse, mockFilterChain)

        then: "security context is null"
        SecurityContextHolder.getContext().getAuthentication() == null
    }

    def "security context should be null when token in header is not valid"() {
        given: "request with invalid token in header"
        mockRequest.addHeader(authHeader, "Bearer "+jwt+"++++")

        when: "filter internal logic is run"
        filter.doFilter(mockRequest, mockResponse, mockFilterChain)

        then: "security context is null"
        SecurityContextHolder.getContext().getAuthentication() == null
    }

    def "security context should not be null when token in header is valid"() {
        given: "request with valid token in header"
        mockRequest.addHeader(authHeader, "Bearer "+jwt)

        when: "filter internal logic is run"
        filter.doFilter(mockRequest, mockResponse, mockFilterChain)

        then: "security context is not null"
        SecurityContextHolder.getContext().getAuthentication() != null
    }

    def initUserInfo() {
        UserSession userInfo = new UserSession()
        userInfo.id = "user_id"
        userInfo.groupId = "group_id"
        userInfo.firstName = "first"
        userInfo.lastName = "last"
        userInfo.userEmail = "usaer@email.com"

        return userInfo
    }
}
