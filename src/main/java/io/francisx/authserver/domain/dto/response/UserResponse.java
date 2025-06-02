package io.francisx.authserver.domain.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Getter
public class UserResponse {
    private String username;
    private String password;
    private List<String> role;
}
