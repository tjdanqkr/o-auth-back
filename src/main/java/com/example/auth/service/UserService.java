package com.example.auth.service;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.auth.config.JwtTokenUtil;
import com.example.auth.domain.request.LoginRequest;
import com.example.auth.domain.request.SignupRequest;
import com.example.auth.domain.response.LoginResponse;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {


    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtil jwtTokenUtil;

    public List<User> findAll() {
        return userRepository.findAll();
    }



    public void signup(SignupRequest signupRequest) {
        User user = signupRequest.toEntity(passwordEncoder.encode(signupRequest.password()));
        userRepository.save(user);
    }

    public LoginResponse login(LoginRequest loginRequest, HttpServletResponse response) {
        User user = userRepository.findByEmail(loginRequest.email())
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found"));
        if (!passwordEncoder.matches(loginRequest.password(), user.getPassword())) {
            throw new UsernameNotFoundException("User Not Found");
        }
        String accessToken = jwtTokenUtil.generateToken(user);
        String refreshToken = jwtTokenUtil.generateRefreshToken(user.getEmail());
        jwtTokenUtil.setCookieToTokens(response, refreshToken, accessToken);
        return LoginResponse.make(accessToken, refreshToken );
    }
    public void refresh(User user,HttpServletRequest request, HttpServletResponse response) {
        String refreshRequest = jwtTokenUtil.getJwtFromRefreshRequest(request);
        String email = jwtTokenUtil.getEmailFromRefreshJWT(refreshRequest);
        if(!user.getEmail().equals(email)) throw new JWTVerificationException("Invalid refresh token");
        String refreshToken = jwtTokenUtil.generateRefreshToken(user.getEmail());
        String accessToken = jwtTokenUtil.generateToken(user);
        jwtTokenUtil.setCookieToTokens(response, refreshToken, accessToken);
    }
}
