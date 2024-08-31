package com.ecomerce.ms.service.auth.infrastructure.rest.model;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class AuthResponse {
    private String jwtToken;
}
