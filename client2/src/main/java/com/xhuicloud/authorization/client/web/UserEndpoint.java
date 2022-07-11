package com.xhuicloud.authorization.client.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;


@RestController
public class UserEndpoint {

    @Autowired
    private WebClient webClient;

    @GetMapping("/")
    Authentication auth(@RegisteredOAuth2AuthorizedClient("wechat")
                        OAuth2AuthorizedClient authorizedClient) {
        ResponseEntity<Authentication> block = this.webClient
                .get()
                .uri("http://localhost:9090")
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .toEntity(Authentication.class)
                .block();
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
