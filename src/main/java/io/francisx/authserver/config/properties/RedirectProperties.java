package io.francisx.authserver.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "uri")
@Validated
public record RedirectProperties(
        @NotBlank String loginRedirect,
        @NotBlank String logoutRedirect
) {}
