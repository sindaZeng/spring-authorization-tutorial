package com.xhuicloud.authorization.resource.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController("/")
public class UserEndpoint {

    private final List<AuthenticationConverter> authenticationConverters;

    public UserEndpoint(List<AuthenticationConverter> authenticationConverters) {
        this.authenticationConverters = authenticationConverters;
    }

    @GetMapping
    Authentication auth() {
        System.out.println(authenticationConverters);
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
