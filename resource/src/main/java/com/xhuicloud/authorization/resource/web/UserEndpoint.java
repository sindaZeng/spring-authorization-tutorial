package com.xhuicloud.authorization.resource.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("/")
public class UserEndpoint {

    @GetMapping
    String index() {
        return "success";
    }
}