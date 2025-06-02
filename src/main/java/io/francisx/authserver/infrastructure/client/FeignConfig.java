package io.francisx.authserver.infrastructure.client;

import feign.RequestInterceptor;
import io.francisx.authserver.infrastructure.security.TokenService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FeignConfig {

    /**
     * This method adds to header the bearer token calling token service
     * @param tokenService Calls token service to create a 5 minute bearer token to access user-service
     * @return templateHeader
     */
    @Bean
    RequestInterceptor oauth2FeignRequestInterceptor(TokenService tokenService) {
        return requestTemplate ->
                requestTemplate.header("Authorization",
                        "Bearer " + tokenService.getClientCredentialsToken());
    }
}
