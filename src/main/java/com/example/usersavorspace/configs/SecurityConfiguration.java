package com.example.usersavorspace.configs;

import com.example.usersavorspace.services.CustomOAuth2UserService;
import com.example.usersavorspace.services.GithubOAuth2UserService;
import com.example.usersavorspace.services.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {


    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String googleClientSecret;

    @Value("${spring.security.oauth2.client.registration.github.client-id}")
    private String githubClientId;

    @Value("${spring.security.oauth2.client.registration.github.client-secret}")
    private String githubClientSecret;


    private final AuthenticationProvider authenticationProvider;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final GithubOAuth2UserService githubOAuth2UserService;
    private final JwtService jwtService;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final GithubOAuth2LoginSuccessHandler githubOAuth2LoginSuccessHandler;

    public SecurityConfiguration(
            JwtAuthenticationFilter jwtAuthenticationFilter,
            AuthenticationProvider authenticationProvider,
            CustomOAuth2UserService customOAuth2UserService,
            JwtService jwtService,
            OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler,
            GithubOAuth2LoginSuccessHandler githubOAuth2LoginSuccessHandler,
            GithubOAuth2UserService githubOAuth2UserService
    ) {
        this.authenticationProvider = authenticationProvider;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.customOAuth2UserService = customOAuth2UserService;
        this.jwtService = jwtService;
        this.oAuth2LoginSuccessHandler = oAuth2LoginSuccessHandler;
        this.githubOAuth2LoginSuccessHandler = githubOAuth2LoginSuccessHandler;
        this.githubOAuth2UserService = githubOAuth2UserService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .requiresChannel(channel -> channel
                        .requestMatchers(r -> r.getHeader("X-Forwarded-Proto") != null)
                        .requiresSecure())
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login","/error","/auth/login", "/auth/signup", "/auth/refresh-token",
                                "/auth/email", "/auth/login-admin", "/auth/create-admin",
                                "/auth/reactivate", "/auth/deactivate", "/auth/forgot-password",
                                "/oauth2/**", "/login/oauth2/code/*").permitAll()
                        .requestMatchers("/auth/verify-token").authenticated()
                        .requestMatchers("/Pictures/**", "/uploads/**").permitAll()
                        .requestMatchers("/admin/**").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/admin/comments/*", "/admin/recipes/*").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/comments/**").permitAll()
                        .requestMatchers(HttpMethod.DELETE, "/api/comments/**").permitAll()
                        .requestMatchers("/api/notifications/**").permitAll()
                        .requestMatchers("/ws/**", "/ws", "/topic/**", "/topic", "/app/**").permitAll()
                        .requestMatchers(HttpMethod.PUT, "/api/comments/*/flag").authenticated()
                        .requestMatchers("/users/change-password", "/users/*/reactivate").authenticated()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(authorization -> authorization
                                .baseUri("/oauth2/authorization"))
                        .redirectionEndpoint(redirection -> redirection
                                .baseUri("/login/oauth2/code/*"))
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(compositeOAuth2UserService()))
                                .successHandler(oAuth2LoginSuccessHandler)
                                .failureHandler(((request, response, exception) -> {
                                    log.error("OAuth2 login failure", exception);
                                    response.sendRedirect("https://savorspace.systems/homepage?error=login_failed");
                                })
                        )
                        .successHandler((request, response, authentication) -> {
                            String clientRegistrationId = ((OAuth2AuthenticationToken) authentication)
                                    .getAuthorizedClientRegistrationId();

                            if ("github".equals(clientRegistrationId)) {
                                githubOAuth2LoginSuccessHandler.onAuthenticationSuccess(request, response, authentication);
                            } else {
                                oAuth2LoginSuccessHandler.onAuthenticationSuccess(request, response, authentication);
                            }
                        })
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                            response.getWriter().write("Unauthorized" + authException.getMessage());
                        })
                );

        return http.build();
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> compositeOAuth2UserService() {
        return request -> {
            String registrationId = request.getClientRegistration().getRegistrationId();
            if ("google".equals(registrationId)) {
                return customOAuth2UserService.loadUser(request);
            } else if ("github".equals(registrationId)) {
                return githubOAuth2UserService.loadUser(request);
            }
            throw new OAuth2AuthenticationException("Unsupported OAuth2 provider");
        };
    }

    private class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                            Authentication authentication) throws IOException, ServletException {
            String clientRegistrationId = ((OAuth2AuthenticationToken) authentication)
                    .getAuthorizedClientRegistrationId();

            try {
                if ("github".equals(clientRegistrationId)) {
                    githubOAuth2LoginSuccessHandler.onAuthenticationSuccess(request, response, authentication);
                } else {
                    oAuth2LoginSuccessHandler.onAuthenticationSuccess(request, response, authentication);
                }
            } catch (Exception e) {
                logger.error("Error in OAuth2 authentication success handler", e);
                response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                response.getWriter().write("Authentication error: " + e.getMessage());
            }
        }
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:5173", "https://penguinman.me", "https://penguinman-backend-production.up.railway.app", "https://savorspace.systems")); // Allow requests from this origin
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers"
        ));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        configuration.setAllowCredentials(true);
        //Add exposed headers
        configuration.setExposedHeaders(List.of("Authorization", "Refresh-Token"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}