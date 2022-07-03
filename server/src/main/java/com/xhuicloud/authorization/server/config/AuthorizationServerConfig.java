package com.xhuicloud.authorization.server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.xhuicloud.authorization.server.jose.Jwks;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2ClientAuthenticationConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.UUID;

@EnableWebSecurity(debug = true)
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

//        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
//                new OAuth2AuthorizationServerConfigurer<>();
//
//        RequestMatcher endpointsMatcher = authorizationServerConfigurer
//                .getEndpointsMatcher();
//
//        http
//                .requestMatcher(endpointsMatcher)
//                .authorizeRequests(authorizeRequests ->
//                        authorizeRequests.anyRequest().authenticated()
//                )
//                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
//                .apply(authorizationServerConfigurer);
//        authorizationServerConfigurer
//                .tokenGenerator(tokenGenerator());

        http
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/toLogin"))
                );
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .antMatchers("/oauth2/**")
                        .permitAll() //匹配这个url 放行
                        .anyRequest().authenticated()
                )
//                .formLogin(withDefaults());
                .formLogin()
                // 自定义登录页
                .loginPage("/toLogin")
                .loginProcessingUrl("/login")
                .permitAll()
                .and().csrf().disable();//跨站请求伪造攻击
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(userDetails);
    }
//    @Bean
    public OAuth2TokenGenerator oAuth2TokenGenerator() {
        CustomOAuth2TokenGenerator accessTokenGenerator = new CustomOAuth2TokenGenerator();
        return new DelegatingOAuth2TokenGenerator(accessTokenGenerator, new OAuth2RefreshTokenGenerator());
    }


    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        RegisteredClient client = registeredClientRepository.findByClientId("client");
        if (client == null) {
            RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("client")
                    .clientSecret("{noop}secret")
                    // 授权方法
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .redirectUri("http://127.0.0.1:9090/authorized")
                    .redirectUri("https://baidu.com")
                    .scope(OidcScopes.OPENID)
                    .scope("message.read")
                    .scope("message.write")
                    // 客户端配置
                    .clientSettings(ClientSettings.builder()
                            .requireAuthorizationConsent(true)
                            .build())
                    // token配置
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofDays(365))
//                            .accessTokenFormat(OAuth2TokenFormat.REFERENCE) // 生成“不透明”令牌
                            .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) // 生成jwt
                            .build())
                    .build();
             registeredClientRepository.save(registeredClient);
        }
        return registeredClientRepository;
    }

    /**
     * 配置此Bean 才会拥有/oauth2/jwks端点 用于获取解密密钥
     *
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer() {
        return context -> {
            OAuth2TokenClaimsSet.Builder claims = context.getClaims();
            // Customize claims
            claims.claim("app","xhuicloud");
        };
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().issuer("http://localhost:8080").build();
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

//    @Bean
//    public EmbeddedDatabase embeddedDatabase() {
//        // @formatter:off
//        return new EmbeddedDatabaseBuilder()
//                .generateUniqueName(true)
//                .setType(EmbeddedDatabaseType.H2)
//                .setScriptEncoding("UTF-8")
//                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
//                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
//                .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
//                .build();
//        // @formatter:on
//    }

}
