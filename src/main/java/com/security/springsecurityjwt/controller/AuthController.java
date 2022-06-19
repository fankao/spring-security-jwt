package com.security.springsecurityjwt.controller;

import com.security.springsecurityjwt.model.exception.BadRequestException;
import com.security.springsecurityjwt.model.exception.NotFoundException;
import com.security.springsecurityjwt.payload.request.LoginRequest;
import com.security.springsecurityjwt.payload.request.LogoutRequest;
import com.security.springsecurityjwt.payload.request.SignupRequest;
import com.security.springsecurityjwt.payload.request.TokenRefreshRequest;
import com.security.springsecurityjwt.payload.response.JwtResponse;
import com.security.springsecurityjwt.payload.response.MessageResponse;
import com.security.springsecurityjwt.service.AuthService;
import com.security.springsecurityjwt.service.TokenRefreshService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    private AuthService authService;
    @Autowired
    private TokenRefreshService tokenRefreshService;

    @PostMapping("/signIn")
    public ResponseEntity<JwtResponse> signIn(@Valid @RequestBody LoginRequest loginRequest) throws NotFoundException {
        return ResponseEntity.ok(authService.signIn(loginRequest));
    }

    @PostMapping("/signUp")
    public ResponseEntity<MessageResponse> registerUser(@Valid @RequestBody SignupRequest signupRequest) throws Exception {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(authService.signUp(signupRequest));
    }

    @PostMapping("/refreshToken")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest tokenRefreshRequest) throws BadRequestException {
        return ResponseEntity.ok(tokenRefreshService.refreshToken(tokenRefreshRequest));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@Valid @RequestBody LogoutRequest logoutRequest) {
        tokenRefreshService.deleteByUserId(logoutRequest.getUserId());
        return ResponseEntity.noContent().build();
    }
}
