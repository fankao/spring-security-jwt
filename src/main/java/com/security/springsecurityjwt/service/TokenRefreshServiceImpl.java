package com.security.springsecurityjwt.service;

import com.security.springsecurityjwt.jwt.JwtUtils;
import com.security.springsecurityjwt.model.RefreshToken;
import com.security.springsecurityjwt.model.User;
import com.security.springsecurityjwt.model.exception.BadRequestException;
import com.security.springsecurityjwt.model.exception.NotFoundException;
import com.security.springsecurityjwt.model.exception.TokenRefreshException;
import com.security.springsecurityjwt.payload.request.TokenRefreshRequest;
import com.security.springsecurityjwt.payload.response.TokenRefreshResponse;
import com.security.springsecurityjwt.repository.RefreshTokenRepository;
import com.security.springsecurityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
public class TokenRefreshServiceImpl implements TokenRefreshService {
    @Value("${security.app.jwtRefreshExpirationMs}")
    private Long refreshTokenDurationMs;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JwtUtils jwtUtils;
    @Override
    public RefreshToken createRefreshToken(Long userId) throws NotFoundException {
        User user = userRepository.findById(userId).orElse(null);
        if(Objects.isNull(user)){
            throw new NotFoundException("Not found user with user id: "+userId);
        }
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    @Override
    public boolean deleteByUserId(Long userId) {
        refreshTokenRepository.deleteByUserId(userId);
        return true;
    }


    @Override
    public RefreshToken verifyExpiration(RefreshToken refreshToken) {
        if (refreshToken.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(refreshToken);
            throw new TokenRefreshException(refreshToken.getToken(), "Refresh token was expired. Please make a new signin request");
        }
        return refreshToken;
    }

    @Transactional
    @Override
    public TokenRefreshResponse refreshToken(TokenRefreshRequest tokenRefreshRequest) throws BadRequestException {
        String requestRefreshToken = tokenRefreshRequest.getRefreshToken();
        TokenRefreshResponse refreshToken = refreshTokenRepository.findByToken(requestRefreshToken)
                .map(token -> verifyExpiration(token))
                .map(RefreshToken::getUser)
                .map(user -> processTokenRefreshResponse(user))
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken, "Refresh token is not in database!"));
        if(Objects.isNull(requestRefreshToken)){
            throw new BadRequestException("Cannot refresher token. Please sign in again!");
        }
        return refreshToken;
    }

    private TokenRefreshResponse processTokenRefreshResponse(User user) {
        String accessToken = jwtUtils.generateTokenFromUsername(user.getUsername());
        String newRefreshToken = rotateRefreshToken(user);
        if (Objects.isNull(newRefreshToken)) {
            return null;
        }
        return new TokenRefreshResponse(accessToken, newRefreshToken);
    }

    private String rotateRefreshToken(User user){
        try {
            deleteByUserId(user.getId());
            return createRefreshToken(user.getId()).getToken();
        } catch (NotFoundException e) {
            return null;
        }
    }
}
