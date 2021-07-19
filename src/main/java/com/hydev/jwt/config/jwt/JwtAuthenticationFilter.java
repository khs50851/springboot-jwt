package com.hydev.jwt.config.jwt;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hydev.jwt.config.auth.PrincipalDetails;
import com.hydev.jwt.model.User;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에UsernamePasswordAuthenticationFilter 이게 있음 언제 동작하냐면
// 내가 login요청해서 username,password를 포스트로 보내면 동작함 근데 지금은 formlogin.disable때매 작동안함 그래서 이렇게 직접 만들어서 등록

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
	
	private final AuthenticationManager authenticationManager;
	
	
	// login 요청을 하면 로그인 시도를 위해 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter 로그인 시도함");
		
		// 1. 유저네임, 패스워드 받아서
		// 2. 정상인지 로그인 시도 해보는것 authenticationManager로 로그인시도하면 principalDetailsService가 호출됨
		// 3. loacUserByUsername이 자동으로 실행 그리고 principalDetails를 세션에 담고 
		// 4. jwt 토큰을 만들어서 응답해주면됨
		// 굳이 principaldetails을 세션에 담는 이유는 권한관리때문
		
		try {
			/*
			BufferedReader br = request.getReader();
			String input = null;
			while((input = br.readLine()) != null) {
				System.out.println("input : "+input);
			}
				*/
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class); // 제이슨 데이터 객체에 집어넣기
			System.out.println(user);
			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()); // 토큰 생성
			// principalDatailService의  loacUserByUsername가 실행됨 authentication 여기엔 내 로그인한 정보가 담김
			Authentication authentication = authenticationManager.authenticate(authenticationToken);
			
			PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
			System.out.println(principalDetails.getUser().getUsername());
			//System.out.println(request.getInputStream().toString()); // 이 스트림 안에 user랑 password담겨있음
			System.out.println("1========================");
			
			// authentication 객체가 session 영역에 저장됨
			return authentication;
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("2==================");
		return null;
		
		
	}
	// authenticationManager로 로그인시도를 하면
	// principaldetailsService가 loadUser~함수 실행
	
	// attemptAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication 실행됨
	// 이 함수에서 JWT 토큰을 만들어서 request요청한 사용자에게 토큰 response해주면됨
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
		
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		
		// RSA방식이 아니라 Hash방식
		String jwtToken = JWT.create()
				.withSubject("cap토큰")
				.withExpiresAt(new Date(System.currentTimeMillis()+(60000*10))) // 만료시간(이 토큰의 유효시간) 1/1000 유효시간 10분
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.withClaim("roles", principalDetails.getUser().getRoles())
				.sign(Algorithm.HMAC512("hy"));
		
		System.out.println("successfulAuthentication 실행됨 : 인증 완료되었다는 뜻");
		response.addHeader("Authorization", "Bearer "+jwtToken); // 헤더에 담아서 사용자에게 응답
	}
	
}
