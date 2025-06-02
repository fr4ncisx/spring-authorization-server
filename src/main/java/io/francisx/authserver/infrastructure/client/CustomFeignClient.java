package io.francisx.authserver.infrastructure.client;

import io.francisx.authserver.domain.dto.response.UserResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(value = "${feign.user-service.name}", configuration = FeignConfig.class)
public interface CustomFeignClient {

    /**
     * You should have a {@code HTTP GET Method} in path {@code http://user-service}
     * and get the User(username, password, and a list of roles)
     * This route needs to be protected in SecurityConfig(User-service)
     * with authority {@code SCOPE_READ} as we use Auth-Server with that scope
     * @param username Current username to compare with login
     * @return The response of user-service (application/json)
     */
    @GetMapping
    UserResponse findByUsername(@RequestParam String username);
}
