package io.francisx.authserver.domain.dto.response;

import java.util.List;

public record UserResponse(String username, String password, List<String> role) {}
