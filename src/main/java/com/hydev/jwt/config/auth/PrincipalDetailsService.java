package com.hydev.jwt.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.hydev.jwt.model.User;
import com.hydev.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

// http://localhost:8095/login이 호출될때 동작

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService{
	
	private final UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		System.out.println("principalDetailsService의 loadUserByusername() 실행");
		User userEntity = userRepository.findByUsername(username);
		if(userEntity != null) {
			return new PrincipalDetails(userEntity); // 이거 리턴은 session(Authentication(내부 UserDetails)) 이렇게 들어가게됨
		}
		return null;
	}
	
	
}
