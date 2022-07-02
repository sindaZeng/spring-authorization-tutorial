package com.xhuicloud.authorization.resource.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;

@Component
public class CustomOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final OAuth2AuthorizationService authorizationService;

    public CustomOpaqueTokenIntrospector(@Autowired JdbcTemplate jdbcTemplate) {
        this.authorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, new JdbcRegisteredClientRepository(jdbcTemplate));
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2Authorization oldAuthorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        return null;
    }
}
