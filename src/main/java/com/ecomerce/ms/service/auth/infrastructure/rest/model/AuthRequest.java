package com.ecomerce.ms.service.auth.infrastructure.rest.model;

import lombok.Getter;

@Getter
public class AuthRequest {
    private String username;
    private String password;
}
