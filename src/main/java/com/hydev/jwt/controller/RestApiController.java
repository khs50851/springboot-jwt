package com.hydev.jwt.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.hydev.jwt.config.auth.PrincipalDetails;
import com.hydev.jwt.model.User;
import com.hydev.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class RestApiController {
	
	private final UserRepository userRepository;
	private final BCryptPasswordEncoder passwordEncoder;
	
	@GetMapping("home")
	public String home() {
		return "<h1>home</h1>";
	}
	
	@PostMapping("join")
	public String join(@RequestBody User user) {
		System.out.println("join 요청");
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "회원가입 완료";
	}
	
	@PostMapping("token")
	public String token() {
		return "<h1>token</h1>";
	}
	
	// 유저,매니저,어드민 권한만 접근 가능
	@GetMapping("/api/v1/user")
	public String user(Authentication authentication) {
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("authentication : "+principalDetails.getUsername());
		
		return "user";
	}
	
	// 매니저,어드민
	@GetMapping("/api/v1/manager")
	public String manager() {
		return "manager";
	}
	
	//어드민만
	@GetMapping("/api/v1/admin")
	public String admin() {
		return "admin";
	}
	
	
}
