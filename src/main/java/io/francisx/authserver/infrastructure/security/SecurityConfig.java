package io.francisx.authserver.infrastructure.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.francisx.authserver.config.properties.AppSecurityProperties;
import io.francisx.authserver.config.properties.OAuth2ClientProperties;
import io.francisx.authserver.config.properties.RedirectProperties;
import io.francisx.authserver.config.properties.RsaKeyProperties;
import io.francisx.authserver.infrastructure.security.ratelimit.RateLimitingFilter;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final AppSecurityProperties appSecurityProperties;
    private final RedirectProperties redirectProperties;
    private final OAuth2ClientProperties oAuth2ClientProperties;
    private final RsaKeyProperties rsaKeyProperties;
    private final RateLimitingFilter rateLimitingFilter;

    public SecurityConfig(
            AppSecurityProperties appSecurityProperties,
            RedirectProperties redirectProperties,
            OAuth2ClientProperties oAuth2ClientProperties,
            RsaKeyProperties rsaKeyProperties,
            RateLimitingFilter rateLimitingFilter
    ) {
        this.appSecurityProperties = appSecurityProperties;
        this.redirectProperties = redirectProperties;
        this.oAuth2ClientProperties = oAuth2ClientProperties;
        this.rsaKeyProperties = rsaKeyProperties;
        this.rateLimitingFilter = rateLimitingFilter;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        var authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        return http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, authServer ->
                        authServer.oidc(Customizer.withDefaults()))
                .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .cors(Customizer.withDefaults())
                .build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/health/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .cors(Customizer.withDefaults())
                .headers(headers -> headers
                        .frameOptions(frame -> frame.deny())
                        .contentTypeOptions(Customizer.withDefaults())
                        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000)))
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public ApplicationRunner clientInitializer(RegisteredClientRepository registeredClientRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (registeredClientRepository.findByClientId(oAuth2ClientProperties.clientid().serviceClient()) == null) {
                registeredClientRepository.save(getUserServiceClient(passwordEncoder));
            }
            if (registeredClientRepository.findByClientId(oAuth2ClientProperties.clientid().oidcClient()) == null) {
                registeredClientRepository.save(getOidcClient(passwordEncoder));
            }
        };
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = loadOrGenerateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(rsaKeyProperties.keyId())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private KeyPair loadOrGenerateKeyPair() {
        if (rsaKeyProperties.privateKey() != null && !rsaKeyProperties.privateKey().isBlank()
                && rsaKeyProperties.publicKey() != null && !rsaKeyProperties.publicKey().isBlank()) {
            return parsePemKeyPair(rsaKeyProperties.publicKey(), rsaKeyProperties.privateKey());
        }
        if (rsaKeyProperties.keystorePath() != null && !rsaKeyProperties.keystorePath().isBlank()) {
            return loadKeyStore(
                    rsaKeyProperties.keystorePath(),
                    rsaKeyProperties.keystorePassword() != null ? rsaKeyProperties.keystorePassword() : "changeit",
                    rsaKeyProperties.keyAlias() != null ? rsaKeyProperties.keyAlias() : "auth-key"
            );
        }
        return loadOrGenerateDefaultKeystore();
    }

    private KeyPair parsePemKeyPair(String publicKeyPem, String privateKeyPem) {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            String cleanPub = publicKeyPem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] pubBytes = Base64.getDecoder().decode(cleanPub);
            RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(pubBytes));

            String cleanPriv = privateKeyPem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] privBytes = Base64.getDecoder().decode(cleanPriv);
            RSAPrivateKey privateKey = (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));

            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse RSA keys from PEM configuration", e);
        }
    }

    private KeyPair loadKeyStore(String path, String password, String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream is = Files.newInputStream(Path.of(path))) {
                keyStore.load(is, password.toCharArray());
            }
            RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey(alias, password.toCharArray());
            RSAPublicKey publicKey = (RSAPublicKey) keyStore.getCertificate(alias).getPublicKey();
            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA key pair from keystore at " + path, e);
        }
    }

    private KeyPair loadOrGenerateDefaultKeystore() {
        Path path = Path.of("auth-keystore.p12");
        String password = "changeit";
        String alias = "auth-key";
        if (Files.exists(path)) {
            return loadKeyStore(path.toString(), password, alias);
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            X509Certificate certificate = generateSelfSignedCertificate(keyPair);

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, password.toCharArray());
            keyStore.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), new java.security.cert.Certificate[]{certificate});

            try (OutputStream os = Files.newOutputStream(path)) {
                keyStore.store(os, password.toCharArray());
            }

            return keyPair;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate default persistent RSA keystore", e);
        }
    }

    private static X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
        byte[] v3 = der(0xa0, der(0x02, new byte[]{0x02}));
        byte[] serial = der(0x02, new byte[]{0x01});
        byte[] sha256withRsaOid = der(0x06, new byte[]{0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x0b});
        byte[] sigAlg = seq(sha256withRsaOid, new byte[]{0x05, 0x00});
        byte[] cnOid = der(0x06, new byte[]{0x55, 0x04, 0x03});
        byte[] cnVal = der(0x0c, "auth-server".getBytes(StandardCharsets.UTF_8));
        byte[] atv = seq(cnOid, cnVal);
        byte[] rdn = der(0x31, atv);
        byte[] issuer = der(0x30, rdn);
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        byte[] notBefore = der(0x17, fmt.format(Instant.now().minus(1, ChronoUnit.DAYS)).getBytes(StandardCharsets.US_ASCII));
        byte[] notAfter = der(0x17, fmt.format(Instant.now().plus(3650, ChronoUnit.DAYS)).getBytes(StandardCharsets.US_ASCII));
        byte[] validity = seq(notBefore, notAfter);
        byte[] subject = issuer;
        byte[] pubKey = keyPair.getPublic().getEncoded();
        byte[] tbsCert = seq(v3, serial, sigAlg, issuer, validity, subject, pubKey);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(tbsCert);
        byte[] signatureBytes = signature.sign();

        ByteArrayOutputStream bitStringVal = new ByteArrayOutputStream();
        bitStringVal.write(0x00);
        bitStringVal.write(signatureBytes);
        byte[] sigBitString = der(0x03, bitStringVal.toByteArray());

        byte[] certDer = seq(tbsCert, sigAlg, sigBitString);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certDer));
    }

    private static byte[] der(int tag, byte[] val) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int len = val.length;
        if (len < 128) {
            out.write(len);
        } else if (len < 256) {
            out.write(0x81);
            out.write(len);
        } else {
            out.write(0x82);
            out.write((len >> 8) & 0xff);
            out.write(len & 0xff);
        }
        out.write(val, 0, val.length);
        return out.toByteArray();
    }

    private static byte[] seq(byte[]... items) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] b : items) {
            out.write(b);
        }
        return der(0x30, out.toByteArray());
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(appSecurityProperties.authserverUri())
                .build();
    }

    private RegisteredClient getUserServiceClient(PasswordEncoder passwordEncoder) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(oAuth2ClientProperties.clientid().serviceClient())
                .clientSecret(passwordEncoder.encode(appSecurityProperties.secretKey()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope(oAuth2ClientProperties.client().scope())
                .build();
    }

    private RegisteredClient getOidcClient(PasswordEncoder passwordEncoder) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(oAuth2ClientProperties.clientid().oidcClient())
                .clientSecret(passwordEncoder.encode(appSecurityProperties.secretKey()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(redirectProperties.loginRedirect())
                .postLogoutRedirectUri(redirectProperties.logoutRedirect())
                .scope("read")
                .scope("write")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build())
                .build();
    }
}
