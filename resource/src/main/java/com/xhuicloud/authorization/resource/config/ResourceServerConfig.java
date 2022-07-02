package com.xhuicloud.authorization.resource.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity(debug = true)
public class ResourceServerConfig {

    @Autowired
    private OpaqueTokenIntrospector opaqueTokenIntrospector;
    @Autowired
    private CustomBearerTokenResolver customBearerTokenResolver;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.oauth2ResourceServer().jwt(); // jwt 使用这个
        http.oauth2ResourceServer().opaqueToken(opaqueTokenConfigurer -> {
            opaqueTokenConfigurer.introspector(opaqueTokenIntrospector);
        }).bearerTokenResolver(customBearerTokenResolver); // 不透明令牌模式
        return http.build();
    }


}
