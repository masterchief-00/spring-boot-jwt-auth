package com.jwt.auth.spring_boot_jwt_auth.user;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, String> {

    Optional<User> findByEmail(String email);

}
