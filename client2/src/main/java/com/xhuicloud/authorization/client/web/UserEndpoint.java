package com.xhuicloud.authorization.client.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class UserEndpoint {

    @GetMapping("/authorization")
    Authentication auth() {
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
