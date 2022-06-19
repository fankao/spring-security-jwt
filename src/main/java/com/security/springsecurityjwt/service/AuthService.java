package com.security.springsecurityjwt.service;

import com.security.springsecurityjwt.model.exception.NotFoundException;
import com.security.springsecurityjwt.payload.request.LoginRequest;
import com.security.springsecurityjwt.payload.request.SignupRequest;
import com.security.springsecurityjwt.payload.request.TokenRefreshRequest;
import com.security.springsecurityjwt.payload.response.JwtResponse;
import com.security.springsecurityjwt.payload.response.MessageResponse;
import com.security.springsecurityjwt.payload.response.TokenRefreshResponse;

public interface AuthService {
    /**
     * 1.authenticate { username, password }
     * 2.update SecurityContext using Authentication object
     * 3.generate JWT
     * 4.get UserDetails from Authentication object
     * 5.response contains JWT and UserDetails data
     * @param loginRequest
     * @return JwtResponse
     */
    JwtResponse signIn(LoginRequest loginRequest) throws NotFoundException;

    /**
     * 1.check existing username/email
     * 2.create new User (with ROLE_USER if not specifying role)
     * 3.save User to database using UserRepository
     * @param signupRequest
     * @return
     * @throws Exception
     */
    MessageResponse signUp(SignupRequest signupRequest) throws Exception;
}
