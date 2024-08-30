package com.ecomerce.ms.service.auth.domain.aggregate;

import lombok.Data;

@Data
public class Role {
    private Long id;
    private ERole name;
}
