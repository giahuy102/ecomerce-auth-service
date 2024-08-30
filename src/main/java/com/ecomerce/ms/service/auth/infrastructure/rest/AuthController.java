package com.ecomerce.ms.service.auth.infrastructure.rest;

import com.ecomerce.ms.service.auth.domain.aggregate.UserRepository;
import com.ecomerce.ms.service.auth.infrastructure.jwt.JwtUtils;
import com.ecomerce.ms.service.auth.infrastructure.rest.model.AuthRequest;
import com.ecomerce.ms.service.auth.infrastructure.rest.model.AuthResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @PostMapping(value = "/auth/login")
    public ResponseEntity<AuthResponse> loginUser(@RequestBody AuthRequest authRequest) {
        String username = authRequest.getUsername();
        String password = authRequest.getPassword();
        Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        String jwtToken = jwtUtils.generateJwtToken(auth);
        return ResponseEntity.ok(AuthResponse.builder().jwtToken(jwtToken).build());
    }

    @PostMapping(value = "/auth/register")
    public ResponseEntity<String> registerUser(@RequestBody AuthRequest authRequest) {
        userRepository.insertUser(authRequest.getUsername(), passwordEncoder.encode(authRequest.getPassword()));
        return ResponseEntity.ok("Successfully insert user");
    }

    @PostMapping(value = "/test")
    public ResponseEntity<String> test(@RequestBody AuthRequest authRequest) {
        return ResponseEntity.ok("Successfully insert user");
    }
}
