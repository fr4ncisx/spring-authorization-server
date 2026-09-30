package io.francisx.authserver.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "services.user-service")
@Validated
public record UserServiceProperties(
        @NotBlank String url,
        @Positive int connectTimeout,
        @Positive int readTimeout
) {}
