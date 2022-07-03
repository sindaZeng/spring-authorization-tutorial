package com.xhuicloud.authorization.resource.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController("/")
public class UserEndpoint {

    @GetMapping
    Authentication auth() {
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
