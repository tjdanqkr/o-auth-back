package com.example.auth.controller;

import com.example.auth.config.JwtTokenUtil;
import com.example.auth.domain.request.LoginRequest;
import com.example.auth.domain.request.SignupRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
@Transactional
class AuthControllerTest {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String name = "name";
    private final String email = "email@email.com";
    private final LocalDate birth = LocalDate.now();
    private final String password = "password";
    private final String gender = "남";
    private User user;
    @BeforeEach
    void setUp() {
        user = User.builder()
                .name(name)
                .email(email)
                .birthday(birth)
                .password(passwordEncoder.encode(password))
                .gender(gender)
                .build();
        userRepository.save(user);
    }
    @Test
    void refresh() throws Exception {
        String token = jwtTokenUtil.generateToken(user);
        String refreshToken = jwtTokenUtil.generateRefreshToken(user.getEmail());
        Cookie[] cookies = jwtTokenUtil.makeCookies(token, refreshToken);
        Thread.sleep(1000);
        ResultActions perform = mockMvc.perform(get("/api/v1/auth/refresh")
                .cookie(cookies)
        );
        perform.andExpect(status().isOk())
                .andDo(print())
                .andExpect(cookie().exists("access-token"))
                .andExpect(cookie().exists("refresh-token"));
        Cookie[] cookies1 = perform.andReturn().getResponse().getCookies();
        assertEquals(2, cookies1.length);

        for (int i = 0; i < cookies1.length; i++) {
            assertNotEquals(cookies[i], cookies1[i]);
        }

    }

    @Test
    void signup() throws Exception {
        SignupRequest signupRequest = new SignupRequest("test@test.com", "test", "test1", LocalDate.now().toString(), "남");
        ResultActions perform = mockMvc.perform(
                post("/api/v1/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest))
        );
        perform.andExpect(status().isCreated());

        Assertions.assertEquals(2,userRepository.findAll().size());
    }

    @Test
    void login() throws Exception{
        LoginRequest loginRequest = new LoginRequest(email, password);
        ResultActions perform = mockMvc.perform(post("/api/v1/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest))
        );
        perform.andExpect(status().isOk())
                .andExpect(cookie().exists("access-token"))
                .andExpect(cookie().exists("refresh-token"))
                .andDo(print())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.tokenType").value("Bearer"));

    }
}