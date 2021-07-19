package com.hydev.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.hydev.jwt.model.User;

public interface UserRepository extends JpaRepository<User, Long>{
	public User findByUsername(String username);
}
