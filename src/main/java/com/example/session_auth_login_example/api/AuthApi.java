package com.example.session_auth_login_example.api;

import com.example.session_auth_login_example.dto.AuthDto.LoginRequest;
import com.example.session_auth_login_example.dto.AuthDto.RegisterRequest;
import com.example.session_auth_login_example.entity.User;
import com.example.session_auth_login_example.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.stream.Collectors;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api")
public class AuthApi {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest registerRequest) {
        User user = User.builder()
                .username(registerRequest.username())
                .password(passwordEncoder.encode(registerRequest.password()))
                .roles(registerRequest.roles())
                .build();

        userRepository.save(user);

        return ResponseEntity.ok("계정 등록 성공");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        try {
            // AuthenticationManager를 사용하여 인증 시도
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password())
            );

            // 인증이 성공하면 SecurityContext에 사용자 정보 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 세션 생성 (자동으로 JSESSIONID 쿠키에 저장됨)
            HttpSession session = request.getSession(true); // 새로운 세션 생성
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext()); // SecurityContext를 세션에 저장

            return ResponseEntity.ok("로그인 성공");
        } catch (AuthenticationException e) {
            return ResponseEntity.status(401).body("로그인 실패: " + e.getMessage());
        }
    }

    @GetMapping("/test")
    public ResponseEntity<?> test() {
        // 현재 인증된 사용자 정보 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 사용자 이름 (Principal)
        String username = authentication.getName();

        // 사용자 권한 목록
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(", "));

        // 결과 출력
        String result = String.format("현재 사용자: %s, 권한: %s", username, authorities);

        return ResponseEntity.ok(result);
    }

}
