package io.francisx.authserver.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "oauth2")
@Validated
public record OAuth2ClientProperties(
        @NotNull ClientProperties client,
        @NotNull ClientIdProperties clientid
) {
    public record ClientProperties(@NotBlank String scope) {}
    public record ClientIdProperties(@NotBlank String serviceClient, @NotBlank String oidcClient) {}
}
