package com.example.auth.domain.request;


import com.example.auth.entity.User;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDate;
import java.util.Date;

public record SignupRequest(String email, String password, String name, String birthday, String gender) {
    public User toEntity(String encodedPassword) {
        return User.builder()
                .email(email)
                .password(encodedPassword)
                .name(name)
                .birthday(LocalDate.parse(birthday))
                .gender(gender)
                .build();
    }
}
