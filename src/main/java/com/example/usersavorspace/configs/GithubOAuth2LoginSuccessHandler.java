package com.example.usersavorspace.configs;

import com.example.usersavorspace.entities.User;
import com.example.usersavorspace.services.JwtService;
import com.example.usersavorspace.services.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;


@Component
public class GithubOAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtService jwtService;
    private final UserService userService;
    private static final Logger logger = LoggerFactory.getLogger(GithubOAuth2LoginSuccessHandler.class);

    public GithubOAuth2LoginSuccessHandler(JwtService jwtService, UserService userService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        try {
            OAuth2User oidcUser = (OAuth2User) authentication.getPrincipal();

            String username = oidcUser.getAttribute("login");
            String email = oidcUser.getAttribute("email");
            String name = oidcUser.getAttribute("name");
            String avatarUrl = oidcUser.getAttribute("avatar_url");

            // Fallback email if GitHub email is private
            if (email == null && username != null) {
                email = username + "@github.com";
            }

            String finalEmail = email;
            User user = userService.findByEmail(email).orElseGet(() -> {
                User newUser = new User();
                newUser.setEmail(finalEmail);
                newUser.setFullName(name != null ? name : username);
                newUser.setImageURL(avatarUrl);
                newUser.setRole("USER");
                newUser.setPassword(UUID.randomUUID().toString());
                return userService.save(newUser);
            });

            String token = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            // Set tokens in cookies
            Cookie tokenCookie = new Cookie("authToken", token);
            tokenCookie.setHttpOnly(true);
            tokenCookie.setSecure(true);
            tokenCookie.setPath("/");
            tokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
            response.addCookie(tokenCookie);

            Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(true);
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
            response.addCookie(refreshTokenCookie);

            // Build redirect URL with properly encoded parameters
            String redirectUrl = UriComponentsBuilder
                    .fromUriString("https://savorspace.systems")
                    .path("/homepage")
                    .queryParam("token", URLEncoder.encode(token, StandardCharsets.UTF_8))
                    .queryParam("refreshToken", URLEncoder.encode(refreshToken, StandardCharsets.UTF_8))
                    .build()
                    .toUriString();

            logger.info("Redirecting to: {}", redirectUrl);

            getRedirectStrategy().sendRedirect(request, response, redirectUrl);
        } catch (Exception e) {
            logger.error("Error in GitHub OAuth2 success handler", e);
            response.sendRedirect("https://savorspace.systems/login?error=auth_failed");
        }
    }
}