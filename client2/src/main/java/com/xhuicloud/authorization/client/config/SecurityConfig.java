package com.xhuicloud.authorization.client.config;

import com.xhuicloud.authorization.client.wechat.*;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity(debug = true)
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,  ClientRegistrationRepository clientRegistrationRepository) throws Exception {

        OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService =
                new DelegatingOAuth2UserService<>(Collections.singletonMap("wechat",new WechatOAuth2UserService()));

        OAuth2AuthorizationRequestResolver authorizationRequestResolver = oAuth2AuthorizationRequestResolver(clientRegistrationRepository);
        OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient = accessTokenResponseClient();
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .oauth2Login(loginConfigurer -> loginConfigurer
                        .authorizationEndpoint()
                        // 授权端点配置
                        .authorizationRequestResolver(authorizationRequestResolver)
                        .and()
                        .tokenEndpoint().accessTokenResponseClient(accessTokenResponseClient)
                        .and()
                        // 获取用户信息端点配置
                        .userInfoEndpoint().userService(oAuth2UserService))
                .oauth2Client(withDefaults());
        return http.build();
    }

    private static final String WECHAT_PROVIDER = "wechat";

    private OAuth2AuthorizationRequestResolver oAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository) {
        DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        resolver.setAuthorizationRequestCustomizer(new WechatOAuth2AuthorizationRequestCustomizer(WECHAT_PROVIDER)::customize);
        return resolver;
    }


    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient tokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
        tokenResponseClient.setRequestEntityConverter(new WechatOAuth2AuthorizationCodeGrantRequestEntityConverter());

        OAuth2AccessTokenResponseHttpMessageConverter tokenResponseHttpMessageConverter = new OAuth2AccessTokenResponseHttpMessageConverter();
        // 微信返回的content-type 是 text-plain
        tokenResponseHttpMessageConverter.setSupportedMediaTypes(Arrays.asList(MediaType.APPLICATION_JSON,
                MediaType.TEXT_PLAIN,
                new MediaType("application", "*+json")));
        // 兼容微信解析
        tokenResponseHttpMessageConverter.setAccessTokenResponseConverter(new WechatMapOAuth2AccessTokenResponseConverter());

        RestTemplate restTemplate = new RestTemplate(
                Arrays.asList(new FormHttpMessageConverter(),
                        tokenResponseHttpMessageConverter
                ));

        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        tokenResponseClient.setRestOperations(restTemplate);
        return tokenResponseClient;
    }

}
