package io.francisx.authserver.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "security")
@Validated
public record AppSecurityProperties(
        @NotBlank @Size(min = 32) String secretKey,
        @NotBlank String authserverUri,
        @NotNull TokenProperties token
) {
    public record TokenProperties(@NotBlank String uri) {}
}
