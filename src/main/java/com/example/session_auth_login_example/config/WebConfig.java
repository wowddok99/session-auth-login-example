//package com.example.session_auth_login_example.config;
//
//import org.springframework.context.annotation.Configuration;
//import org.springframework.web.servlet.config.annotation.CorsRegistry;
//import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
//
//@Configuration
//public class WebConfig implements WebMvcConfigurer {
//    @Override
//    public void addCorsMappings(CorsRegistry registry) {
//        registry.addMapping("/**") // 모든 경로에 대해 CORS 허용
//                .allowedHeaders("*")
//                .allowedOrigins("http://localhost:3000") // 특정 출처 허용
//                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // 허용할 HTTP 메서드
//                .allowCredentials(true); // 세션 쿠키를 포함할 수 있도록 설정
//    }
//}
