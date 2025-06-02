package io.francisx.authserver.infrastructure.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Value("${security.authserver-uri}")
    private String issuerAuthServerUri;
    @Value("${uri.login-redirect}")
    private String loginRedirectUri;
    @Value("${uri.logout-redirect}")
    private String logoutRedirectUri;
    @Value("${security.secret-key}")
    private String clientSecretKey;
    @Value("${oauth2.clientid.service-client}")
    private String clientIdServiceClient;
    @Value("${oauth2.client.scope}")
    private String clientScope;
    @Value("${oauth2.clientid.oidc-client}")
    private String clientIdOidc;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        var authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();
        return http.securityMatcher(authorizationServerConfigurer
                        .getEndpointsMatcher())
                .with(authorizationServerConfigurer, authServer ->
                        authServer.oidc(Customizer.withDefaults()))
                .authorizeHttpRequests(authorize -> authorize.anyRequest()
                        .authenticated())
                .formLogin(Customizer.withDefaults())
                .build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest()
                        .authenticated())
                .formLogin(Customizer.withDefaults())
                .cors(Customizer.withDefaults())
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(){
        RegisteredClient oidcClient = getOidcClient();
        RegisteredClient userServiceClient = getUserServiceClient();
        return new InMemoryRegisteredClientRepository(userServiceClient, oidcClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuerAuthServerUri)
                .build();
    }

    private String encodeBcrypt(String rawValue) {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        return encoder.encode(rawValue);
    }

    /**
     * This is the representation of the oauth client only to call UserService to get
     * the User Object
     * @return new oauth client
     */
    private RegisteredClient getUserServiceClient(){
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientIdServiceClient)
                .clientSecret(encodeBcrypt(clientSecretKey))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope(clientScope)
                .build();
    }

    /**
     * This is the representation of the oauth client with high privileges having scope {@code read} and {@code write}
     * @return new oauth client with read and write scopes
     */
    private RegisteredClient getOidcClient(){
        return RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId(clientIdOidc)
                .clientSecret(encodeBcrypt(clientSecretKey))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(loginRedirectUri)
                .postLogoutRedirectUri(logoutRedirectUri)
                .scope("read")
                .scope("write")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .build())
                .build();
    }
}
