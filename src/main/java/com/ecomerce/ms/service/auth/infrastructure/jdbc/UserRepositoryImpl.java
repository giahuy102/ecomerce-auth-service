package com.ecomerce.ms.service.auth.infrastructure.jdbc;

import com.ecomerce.ms.service.auth.domain.aggregate.User;
import com.ecomerce.ms.service.auth.domain.aggregate.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@RequiredArgsConstructor
@Repository
public class UserRepositoryImpl implements UserRepository {

    private final JdbcTemplate jdbcTemplate;

    public Optional<User> findByUsername(String username) {
        try {
            User userFound = jdbcTemplate.queryForObject(
                    "SELECT username, password FROM users WHERE username = ?",
                    (rs, rowNum) -> {
                        User user = new User();
                        user.setUsername(rs.getString("username"));
                        user.setPassword(rs.getString("password"));
                        return user;
                    },
                    username
            );
            return Optional.of(userFound);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }

    }

    public boolean insertUser(String username, String password) {
        return jdbcTemplate.update("INSERT INTO users(username, password) VALUES(?, ?)", username, password) > 0;
    }
}
