package com.example.session_auth_login_example.config;

import com.example.session_auth_login_example.security.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final CustomUserDetailsService customUserDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(request -> {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(List.of("http://localhost:3000")); // 허용할 출처
                config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS")); // 허용할 HTTP 메서드
                config.setAllowedHeaders(List.of("*")); // 허용할 HTTP 헤더
                config.setAllowCredentials(true); // 세션 쿠키를 포함할 수 있도록 설정
                return config;
            }))
            .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                    .requestMatchers("/api/login", "/api/register").permitAll() // 로그인, 회원가입은 모든 사용자 접근 허용
                    .requestMatchers("/api/test").hasAuthority("ROLE_ADMIN")
                    .anyRequest().authenticated() // 나머지 요청은 인증 필요
            )
            .formLogin(form -> form
                    .loginProcessingUrl("/login") // 로그인 처리 URL
                    .usernameParameter("username") // 사용자 이름 파라미터
                    .passwordParameter("password") // 비밀번호 파라미터
                    .defaultSuccessUrl("/home", true) // 로그인 성공 후 리다이렉트 URL
            )
            .logout(logout -> logout
                    .logoutUrl("/logout") // 로그아웃 URL
                    .logoutSuccessUrl("/login") // 로그아웃 후 리다이렉트 URL
                    .invalidateHttpSession(true) // 세션 무효화
            )
            .sessionManagement(sessionManagement -> sessionManagement
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 필요 시 세션 생성
            .maximumSessions(1) // 최대 세션 수 설정
            .expiredUrl("/api/login?expired") // 세션 만료 시 리다이렉트할 URL
            )
            .userDetailsService(customUserDetailsService); // UserDetailsService 등록;

        return http.build(); // SecurityFilterChain 반환
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder.userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());

        return authenticationManagerBuilder.build();
    }
}
