package com.example.auth.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Entity
@Builder @AllArgsConstructor @NoArgsConstructor
@Getter @Setter
@Table(name = "USERS")
public class User  implements UserDetails {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "USER_ID")
    private UUID id;
    @Column(unique = true, name="USER_EMAIL")
    private String email;
    @Column(name="USER_PASSWORD")
    private String password;
    @Column(name="USER_NAME")
    private String name;
    @Column(name="USER_BIRTHDAY")
    private LocalDate birthday;
    @Column(name="USER_GENDER")
    private String gender;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(() -> "ROLE_USER");
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return name;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}
