package io.francisx.authserver.infrastructure.client;

import io.francisx.authserver.config.properties.UserServiceProperties;
import io.francisx.authserver.infrastructure.security.TokenService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import java.time.Duration;

@Configuration
public class UserClientConfig {

    @Bean
    public UserClient userClient(UserServiceProperties properties, ObjectProvider<TokenService> tokenServiceProvider) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(Duration.ofMillis(properties.connectTimeout()));
        requestFactory.setReadTimeout(Duration.ofMillis(properties.readTimeout()));

        RestClient restClient = RestClient.builder()
                .baseUrl(properties.url())
                .requestFactory(requestFactory)
                .requestInterceptor((request, body, execution) -> {
                    TokenService tokenService = tokenServiceProvider.getIfAvailable();
                    if (tokenService != null) {
                        request.getHeaders().set(HttpHeaders.AUTHORIZATION, "Bearer " + tokenService.getClientCredentialsToken());
                    }
                    return execution.execute(request, body);
                })
                .build();

        RestClientAdapter adapter = RestClientAdapter.create(restClient);
        HttpServiceProxyFactory factory = HttpServiceProxyFactory.builderFor(adapter).build();
        return factory.createClient(UserClient.class);
    }
}
