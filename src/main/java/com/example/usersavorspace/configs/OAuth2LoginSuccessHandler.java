package com.example.usersavorspace.configs;

import com.example.usersavorspace.entities.User;
import com.example.usersavorspace.services.JwtService;
import com.example.usersavorspace.services.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Component
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserService userService;

    public OAuth2LoginSuccessHandler(JwtService jwtService, UserService userService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        DefaultOidcUser oidcUser = (DefaultOidcUser) authentication.getPrincipal();
        String email = oidcUser.getEmail();
        String name = oidcUser.getFullName();
        String picture = oidcUser.getPicture();

        User user = userService.findByEmail(email).orElseGet(() -> {
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setFullName(name);
            newUser.setImageURL(picture);
            newUser.setRole("USER");
            newUser.setPassword(UUID.randomUUID().toString());
            return userService.save(newUser);
        });

        String token = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        // Use UriComponentsBuilder to properly build and encode the URL
        String redirectUrl = UriComponentsBuilder
                .fromUriString("https://penguinman.me")
                .path("/homepage") // Remove the # and use normal path
                .queryParam("token", token)
                .queryParam("refreshToken", refreshToken)
                .build(false) // Don't encode twice
                .toUriString();

        // Set tokens in headers
        response.setHeader("Authorization", "Bearer " + token);
        response.setHeader("Refresh-Token", refreshToken);
        response.setHeader("Access-Control-Expose-Headers", "Authorization, Refresh-Token");

        // Perform the redirect
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }
}