package com.example.auth.controller;

import com.example.auth.domain.request.LoginRequest;
import com.example.auth.domain.request.SignupRequest;
import com.example.auth.domain.response.LoginResponse;
import com.example.auth.domain.response.UserResponse;
import com.example.auth.entity.User;
import com.example.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    private final UserService userService;
    @GetMapping("/me")
    public UserResponse hello(@AuthenticationPrincipal User user) {
        return UserResponse.of(user);
    }
//    @GetMapping("/user")
//    public List<User> user() {
//        return userService.findAll();
//    }
    @GetMapping("/refresh")
    public void refresh(@AuthenticationPrincipal User user, HttpServletResponse response, HttpServletRequest request) {
        userService.refresh(user, request, response);
    }
    @PostMapping("/signup")
    @ResponseStatus(HttpStatus.CREATED)
    public void signup(@RequestBody SignupRequest signupRequest) {
        userService.signup(signupRequest);
    }

    @PostMapping("/signin")
    public LoginResponse login(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        return userService.login(loginRequest, response);
    }
}
