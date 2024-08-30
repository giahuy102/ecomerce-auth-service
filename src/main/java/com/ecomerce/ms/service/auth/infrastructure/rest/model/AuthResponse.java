package com.ecomerce.ms.service.auth.infrastructure.rest.model;

import lombok.Builder;

@Builder
public class AuthResponse {
    private String jwtToken;
}
