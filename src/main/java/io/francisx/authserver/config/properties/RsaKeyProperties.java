package io.francisx.authserver.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "security.rsa")
@Validated
public record RsaKeyProperties(
        @NotBlank String keyId,
        String privateKey,
        String publicKey,
        String keystorePath,
        String keystorePassword,
        String keyAlias
) {}
