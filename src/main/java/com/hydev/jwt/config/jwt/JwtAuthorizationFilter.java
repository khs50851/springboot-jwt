package com.hydev.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.hydev.jwt.config.auth.PrincipalDetails;
import com.hydev.jwt.model.User;
import com.hydev.jwt.repository.UserRepository;

// 시큐리티가 Filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter라는게 있음.
// 권한이나 인증이 필요한 특정 주소를 요청했을때 위 필터를 무조건 타게 되어 있음
// 권한이나 인증이 필요한 주소가 아니라면 이 필터를 안탐
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{

	private UserRepository userRepository;
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager,UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
		
	}
	
	// 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게됨
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		System.out.println("인증이나 권한 필요한 주소 요청이 됨");
		
		String jwtHeader = request.getHeader("Authorization");
		System.out.println("jwtHeader : "+jwtHeader);
		
		// header가 있는지 확인
		if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
			chain.doFilter(request, response);
			return;
		}
		
		// jwt토큰을 검증해서 정상적인 사용자인지 확인
		String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
		String username = JWT.require(Algorithm.HMAC512("hy")).build().verify(jwtToken).getClaim("username").asString(); // 시크릿값 가져와서 서명하고 정상적이면 유저네임 가져와서 String으로 변환
		
		// 서명 잘됨
		System.out.println("jwtToken : "+jwtToken);
		if(username != null) {
			System.out.println("username : 정상 : "+username);
			User userEntity = userRepository.findByUsername(username);
			System.out.println("userentity : "+userEntity);
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			System.out.println("principaldetails : !!!!"+principalDetails.getUsername());
			System.out.println("principaldetails : "+principalDetails.getUsername()+"sssssss");
			// jwt 토큰 서명을 통해 서명이 정상이면 Authentication 객체를 만들어준다
			Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null,principalDetails.getAuthorities());
			
			SecurityContextHolder.getContext().setAuthentication(authentication); // 강제로 시큐리티 세션에 접근하여 Authentication 객체저장
			
		}
		chain.doFilter(request, response);
	}
	
}
