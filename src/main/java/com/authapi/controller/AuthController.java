package com.authapi.controller;

import com.authapi.model.LoginRequest;
import com.authapi.model.RegisterRequest;
import com.authapi.service.AuthService;
import com.authapi.security.JwtUtil;
import com.authapi.repository.UserRepository;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    @Autowired
    public AuthController(AuthService authService, AuthenticationManager authenticationManager, JwtUtil jwtUtil, UserRepository userRepository) {
        this.authService = authService;
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody RegisterRequest registerRequest) {
        Map<String, String> response = new HashMap<>();
        try {
            String token = authService.register(registerRequest.getEmail(), registerRequest.getPassword());
            response.put("message", "Usuário registrado com sucesso");
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (IllegalArgumentException e) {
            response.put("message", e.getMessage()); // Passa a mensagem de erro para o frontend
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) {
        try {
            // Realiza a autenticação do usuário com as credenciais do LoginRequest
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
            );

            // Se a autenticação for bem-sucedida, armazena no SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Gera o token JWT
            String token = jwtUtil.generateToken(authentication.getName()); // Passa o email (username)

            return ResponseEntity.ok(token);  // Retorna o token no corpo da resposta
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Credenciais inválidas");
        }
    }
}