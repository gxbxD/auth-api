package com.authapi.service;

import com.authapi.model.User;
import com.authapi.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import java.util.ArrayList;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    
    @Autowired
    public UserDetailsServiceImpl(UserRepository userRepository) {
         this.userRepository = userRepository;
    }
    
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
         User user = userRepository.findByEmail(email)
               .orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado com email: " + email));
         // Retorna um objeto UserDetails com o email, senha e uma lista vazia de authorities (você pode ajustar conforme necessário)
         return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), new ArrayList<>());
    }
}
