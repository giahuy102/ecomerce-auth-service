package com.ecomerce.ms.service.auth.infrastructure.security;

import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@Getter
public class JwtAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private final String token;

    public JwtAuthenticationToken(String token) {
        super(null, null);
        this.token = token;
    }
}
