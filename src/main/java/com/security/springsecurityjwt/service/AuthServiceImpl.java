package com.security.springsecurityjwt.service;

import com.security.springsecurityjwt.jwt.JwtUtils;
import com.security.springsecurityjwt.model.ERole;
import com.security.springsecurityjwt.model.RefreshToken;
import com.security.springsecurityjwt.model.Role;
import com.security.springsecurityjwt.model.User;
import com.security.springsecurityjwt.model.exception.BadRequestException;
import com.security.springsecurityjwt.model.exception.NotFoundException;
import com.security.springsecurityjwt.payload.request.LoginRequest;
import com.security.springsecurityjwt.payload.request.SignupRequest;
import com.security.springsecurityjwt.payload.response.JwtResponse;
import com.security.springsecurityjwt.payload.response.MessageResponse;
import com.security.springsecurityjwt.repository.RoleRepository;
import com.security.springsecurityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
@Service
public class AuthServiceImpl implements AuthService {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private TokenRefreshService tokenRefreshService;
    @Transactional
    @Override
    public JwtResponse signIn(LoginRequest loginRequest) throws NotFoundException {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .collect(Collectors.toList());
        tokenRefreshService.deleteByUserId(userDetails.getId());
        return JwtResponse.builder()
                .id(userDetails.getId())
                .username(userDetails.getUsername())
                .email(userDetails.getEmail())
                .roles(roles)
                .accessToken(jwt)
                .refreshToken(tokenRefreshService.createRefreshToken(userDetails.getId()).getToken())
                .type("Bearer")
                .build();
    }

    @Override
    public MessageResponse signUp(SignupRequest signupRequest) throws BadRequestException, NotFoundException {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            throw new BadRequestException("Username is existed");
        }
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new BadRequestException("Email is existed");
        }
        User user = createUser(signupRequest);
        return new MessageResponse("User registered successfully!");
    }

    private User createUser(SignupRequest signupRequest) throws NotFoundException {
        User user = new User();
        user.setUsername(signupRequest.getUsername());
        user.setEmail(signupRequest.getEmail());
        user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
        setRoleForUser(user, signupRequest.getRoles());
        return userRepository.save(user);
    }

    private void setRoleForUser(User user, Set<String> strRoles) {
       Set<Role> roles = new HashSet<>();
       if(CollectionUtils.isEmpty(strRoles)){
           Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                   .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
           roles.add(userRole);
       }else {
           convertStringToRole(roles,strRoles);
       }
       user.setRoles(roles);
    }

    private void convertStringToRole(Set<Role> roles, Set<String> strRoles) {
        strRoles.forEach(role -> {
            switch (role) {
                case "admin":
                    Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(adminRole);
                    break;
                case "mod":
                    Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(modRole);
                    break;
                default:
                    Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(userRole);
            }
        });
    }

}
