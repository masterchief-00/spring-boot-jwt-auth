package com.jwt.auth.spring_boot_jwt_auth.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.jwt.auth.spring_boot_jwt_auth.config.JwtService;
import com.jwt.auth.spring_boot_jwt_auth.user.User;
import com.jwt.auth.spring_boot_jwt_auth.user.UserRepository;
import com.jwt.auth.spring_boot_jwt_auth.user.UserRole;

import lombok.RequiredArgsConstructor;
import lombok.var;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(UserRole.USER)
                .build();

        userRepository.save(user);

        var jwtToken = jwtService.generateTokenLite(user);

        return AuthenticationResponse.builder()
                .authenticationToken(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();

        var jwtToken = jwtService.generateTokenLite(user);

        return AuthenticationResponse.builder()
                .authenticationToken(jwtToken)
                .build();
    }
}
