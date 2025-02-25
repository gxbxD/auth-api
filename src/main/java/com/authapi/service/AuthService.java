package com.authapi.service;

import com.authapi.model.User;
import com.authapi.repository.UserRepository;
import com.authapi.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public String register(String email, String password) {
        if (userRepository.findByEmail(email).isPresent()) {
            throw new IllegalArgumentException("Email já está em uso.");
        }

        if (!isValidEmail(email)) {
            throw new IllegalArgumentException("Email inválido.");
        }

        if (!isValidPassword(password)) {
            throw new IllegalArgumentException("Senha fraca. Use pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais.");
        }

        User user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .build();

        userRepository.save(user);
        return jwtUtil.generateToken(email);
    }

    public String login(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado."));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("Senha incorreta.");
        }

        return jwtUtil.generateToken(email);
    }

    private boolean isValidEmail(String email) {
        return email.matches("^[\\w._%+-]+@[\\w.-]+\\.[a-zA-Z]{2,6}$");
    }

    private boolean isValidPassword(String password) {
        return password.length() >= 8 &&
               password.matches(".*[A-Z].*") &&
               password.matches(".*[a-z].*") &&
               password.matches(".*\\d.*") &&
               password.matches(".*[@#$%^&+=!].*");
    }
}