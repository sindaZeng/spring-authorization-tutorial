package com.xhuicloud.authorization.server.config;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class CustomOAuth2TokenGenerator implements OAuth2TokenGenerator<OAuth2AccessToken> {

    @Override
    public OAuth2AccessToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) || !OAuth2TokenFormat.REFERENCE
                .equals(context.getRegisteredClient().getTokenSettings().getAccessTokenFormat())) {
            return null;
        }

        String issuer = null;
        if (context.getProviderContext() != null) {
            issuer = context.getProviderContext().getIssuer();
        }
        RegisteredClient registeredClient = context.getRegisteredClient();

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());

        // @formatter:off
        OAuth2TokenClaimsSet.Builder claimsBuilder = OAuth2TokenClaimsSet.builder();
        if (StringUtils.hasText(issuer)) {
            claimsBuilder.issuer(issuer);
        }

        claimsBuilder
                .subject(context.getPrincipal().getName())
                .audience(Collections.singletonList(registeredClient.getClientId()))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .notBefore(issuedAt)
                .id(UUID.randomUUID().toString());
        if (!CollectionUtils.isEmpty(context.getAuthorizedScopes())) {
            claimsBuilder.claim(OAuth2ParameterNames.SCOPE, context.getAuthorizedScopes());
        }

        OAuth2TokenClaimsSet accessTokenClaimsSet = claimsBuilder.build();

        String token = String.format("%s:%s:%S", SecurityContextHolder.getContext().getAuthentication().getPrincipal(),
                context.getPrincipal().getName(), UUID.randomUUID());
        return new CustomOAuth2TokenGenerator.OAuth2AccessTokenClaims(OAuth2AccessToken.TokenType.BEARER,
                token, accessTokenClaimsSet.getIssuedAt(), accessTokenClaimsSet.getExpiresAt(),
                context.getAuthorizedScopes(), accessTokenClaimsSet.getClaims());
    }

    private static final class OAuth2AccessTokenClaims extends OAuth2AccessToken implements ClaimAccessor {
        private final Map<String, Object> claims;

        private OAuth2AccessTokenClaims(TokenType tokenType, String tokenValue,
                                        Instant issuedAt, Instant expiresAt, Set<String> scopes, Map<String, Object> claims) {
            super(tokenType, tokenValue, issuedAt, expiresAt, scopes);
            this.claims = claims;
        }

        @Override
        public Map<String, Object> getClaims() {
            return this.claims;
        }

    }
}
