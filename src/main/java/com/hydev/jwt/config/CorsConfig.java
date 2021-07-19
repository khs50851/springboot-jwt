package com.hydev.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {
	
	@Bean
	public CorsFilter corsFilter(){
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true); // 내 서버가 응답할때 json을 자바스크립트에서 처리할 수 있게 할지 설정
		config.addAllowedOrigin("*"); // 모든 IP에 응답 허용
		config.addAllowedHeader("*"); // 모든 헤더에 응답 허용
		config.addAllowedMethod("*"); // 모든 post,get,put,delete, patch 허용
		source.registerCorsConfiguration("/api/**", config); // 이 경로로 들어오는 모든거는 다 config에 따라라
		return new CorsFilter(source);
	}
}
