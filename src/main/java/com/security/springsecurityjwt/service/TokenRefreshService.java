package com.security.springsecurityjwt.service;

import com.security.springsecurityjwt.model.RefreshToken;
import com.security.springsecurityjwt.model.exception.BadRequestException;
import com.security.springsecurityjwt.model.exception.NotFoundException;
import com.security.springsecurityjwt.payload.request.TokenRefreshRequest;
import com.security.springsecurityjwt.payload.response.TokenRefreshResponse;
public interface TokenRefreshService {
    RefreshToken createRefreshToken(Long userId) throws NotFoundException;
    boolean deleteByUserId(Long userId);
    RefreshToken verifyExpiration(RefreshToken refreshToken);
    /**
     * Firstly, we get the Refresh Token from request data
     * Next, get the RefreshToken object {id, user, token, expiryDate} from raw Token using RefreshTokenService
     * We verify the token (expired or not) basing on expiryDate field
     * Continue to use user field of RefreshToken object as parameter to generate new Access Token using JwtUtils
     * Return TokenRefreshResponse if everything is done
     * Or else, throw TokenRefreshException
     * @param tokenRefreshRequest
     * @return
     */
    TokenRefreshResponse refreshToken(TokenRefreshRequest tokenRefreshRequest) throws BadRequestException;
}
