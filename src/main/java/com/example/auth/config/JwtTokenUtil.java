package com.example.auth.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.auth.entity.User;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.util.*;

@Component
public class JwtTokenUtil {
    @Value("${jwt.access-token.name}")
    String ACCESS_TOKEN_NAME;
    @Value("${jwt.access-token.secret}")
    String accessTokenSecret;
    @Value("${jwt.access-token.expiration}")
    Long accessTokenExpiration;

    @Value("${jwt.refresh-token.name}")
    String REFRESH_TOKEN_NAME;
    @Value("${jwt.refresh-token.secret}")
    String refreshTokenSecret;
    @Value("${jwt.refresh-token.expiration}")
    Long refreshTokenExpiration;



    public String generateToken(User user) {
        return JWT.create()
                .withSubject(user.getEmail())
                .withClaim("id", user.getId().toString())
                .withClaim("name",user.getName())
                .withClaim("birthday",user.getBirthday().toString())
                .withExpiresAt(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .sign(Algorithm.HMAC512(accessTokenSecret));
    }
    public String generateRefreshToken(String email) {
        return JWT.create()
                .withSubject(email)
                .withExpiresAt(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                .sign(Algorithm.HMAC512(refreshTokenSecret));
    }
    public User getUserFromJWT(String token) {
        DecodedJWT verify = JWT.require(Algorithm.HMAC512(accessTokenSecret.getBytes()))
                .build()
                .verify(token);
        Map<String, Claim> claims = verify.getClaims();
        String email = verify.getSubject();

        User user = User.builder().id(UUID.fromString(claims.get("id").asString()))
                .email(email)
                .name(claims.get("name").asString())
                .birthday(LocalDate.parse(claims.get("birthday").asString()))
                .build();
        return user;
    }
    public String getEmailFromRefreshJWT(String token) {
        return JWT.require(Algorithm.HMAC512(refreshTokenSecret.getBytes()))
                .build()
                .verify(token)
                .getSubject();
    }

    public boolean validateToken(String authToken) {
        try {
            JWT.require(Algorithm.HMAC512(accessTokenSecret.getBytes()))
                    .build()
                    .verify(authToken);
            return true;
        } catch (JWTVerificationException ex) {
            // Log exception details
            return false;
        }
    }
    public Cookie[] makeCookies(String accessToken,String refreshToken) {
        Cookie refreshTokenCookie = new Cookie(REFRESH_TOKEN_NAME, refreshToken);
        refreshTokenCookie.setMaxAge(refreshTokenExpiration.intValue());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        Cookie accessTokenCookie = new Cookie(ACCESS_TOKEN_NAME, accessToken);
        accessTokenCookie.setMaxAge(accessTokenExpiration.intValue());
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/");
        return new Cookie[]{accessTokenCookie,refreshTokenCookie};
    }
    public void setCookieToTokens(HttpServletResponse response, String refreshToken, String accessToken) {
        Cookie[] responseCookies = makeCookies(accessToken, refreshToken);
        response.addCookie(responseCookies[0]);
        response.addCookie(responseCookies[1]);
    }

    public String getJwtFromRequest(HttpServletRequest request) {
        return getToken(request, ACCESS_TOKEN_NAME);
//        String bearerToken = request.getHeader("Authorization");
//        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
//            return bearerToken.substring(7);
//        }
//        return null;
    }

    public String getJwtFromRefreshRequest(HttpServletRequest request) {
        return getToken(request, REFRESH_TOKEN_NAME);
//        String bearerToken = request.getHeader("Authorization");
//        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
//            return bearerToken.substring(7);
//        }
//        return null;
    }

    @Nullable
    private String getToken(HttpServletRequest request, String refreshTokenName) {
        Cookie[] cookies = request.getCookies();
        if(cookies == null || cookies.length == 0) return null;
        Optional<Cookie> cookieOptional = Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equals(refreshTokenName))
                .findFirst();
        return cookieOptional.map(Cookie::getValue).orElse(null);
    }
}
