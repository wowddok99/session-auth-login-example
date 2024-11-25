package com.example.session_auth_login_example.dto;

import lombok.Builder;

public record AuthDto () {
    @Builder
    public record RegisterRequest(
            String username,
            String password,
            String roles
    ) {}

    @Builder
    public record LoginRequest(
            String username,
            String password
    ) {}
}
