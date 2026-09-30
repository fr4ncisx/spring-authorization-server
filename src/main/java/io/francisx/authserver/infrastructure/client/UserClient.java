package io.francisx.authserver.infrastructure.client;

import io.francisx.authserver.domain.dto.response.UserResponse;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;

@HttpExchange
public interface UserClient {
    @GetExchange("/users/search")
    UserResponse findByUsername(@RequestParam String username);
}
