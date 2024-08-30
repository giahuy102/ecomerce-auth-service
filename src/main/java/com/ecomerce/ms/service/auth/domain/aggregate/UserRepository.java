package com.ecomerce.ms.service.auth.domain.aggregate;

import java.util.Optional;

public interface UserRepository {
    Optional<User> findByUsername(String username);
    boolean insertUser(String username, String password);
}
