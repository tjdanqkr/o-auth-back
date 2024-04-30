package com.example.auth.domain.response;

public record LoginResponse(String accessToken, String refreshToken, String tokenType) {
    public static LoginResponse make(String accessToken, String refreshToken){
        return new LoginResponse(accessToken, refreshToken, "Bearer");

    }
}
