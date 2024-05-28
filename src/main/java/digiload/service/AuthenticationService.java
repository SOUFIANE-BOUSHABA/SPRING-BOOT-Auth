package digiload.service;

import digiload.model.AuthenticationResponse;
import digiload.model.Token;
import digiload.model.User;
import digiload.repository.TokenRepository;
import digiload.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TokenRepository tokenRepository;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepository repository,
                                 PasswordEncoder passwordEncoder,
                                 JwtService jwtService,
                                 TokenRepository tokenRepository,
                                 AuthenticationManager authenticationManager) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.tokenRepository = tokenRepository;
        this.authenticationManager = authenticationManager;
    }

    public ResponseEntity<AuthenticationResponse> register(User user) {
        if (repository.findByUsername(user.getUsername()).isPresent()) {
            return new ResponseEntity<>(HttpStatus.CONFLICT);
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        repository.save(user);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        saveTokens(user, accessToken, refreshToken);

        AuthenticationResponse response = new AuthenticationResponse(accessToken, refreshToken);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    public ResponseEntity<AuthenticationResponse> authenticate(User user) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        User authenticatedUser = repository.findByUsername(user.getUsername()).orElseThrow();

        String accessToken = jwtService.generateAccessToken(authenticatedUser);
        String refreshToken = jwtService.generateRefreshToken(authenticatedUser);
        saveTokens(authenticatedUser, accessToken, refreshToken);

        AuthenticationResponse response = new AuthenticationResponse(accessToken, refreshToken);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    private void saveTokens(User user, String accessToken, String refreshToken) {
        Token token = new Token();
        token.setUser(user);
        token.setAccessToken(accessToken);
        token.setRefreshToken(refreshToken);
        token.setLoggedOut(false);
        tokenRepository.save(token);
    }

    public void logout(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            tokenRepository.findByAccessToken(token).ifPresent(t -> {
                t.setLoggedOut(true);
                tokenRepository.save(t);
            });
        }
    }

    public ResponseEntity<AuthenticationResponse> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String refreshToken = authHeader.substring(7);
            Token token = tokenRepository.findByRefreshToken(refreshToken).orElseThrow();
            User user = token.getUser();

            if (jwtService.isValidRefreshToken(refreshToken, user)) {
                String accessToken = jwtService.generateAccessToken(user);
                token.setAccessToken(accessToken);
                tokenRepository.save(token);
                return new ResponseEntity<>(new AuthenticationResponse(accessToken, refreshToken), HttpStatus.OK);
            }
        }
        return new ResponseEntity<>(HttpStatus.FORBIDDEN);
    }
}