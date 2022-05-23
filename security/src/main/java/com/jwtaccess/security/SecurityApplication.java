package com.jwtaccess.security;

import com.jwtaccess.security.domain.Role;
import com.jwtaccess.security.domain.User;
import com.jwtaccess.security.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService) {

        return  args -> {
            userService.saveRole(new Role(null,"ROLE_USER"));
            userService.saveRole(new Role(null,"ROLE_MANAGER"));
            userService.saveRole(new Role(null,"ROLE_ADMIN"));
            userService.saveRole(new Role(null,"ROLE_SUPER_ADMIN"));

            userService.saveUser(new User(null, "JonDinner","Jon", "12345", new ArrayList<>()));
            userService.saveUser(new User(null, "WillDinner","Will", "12345", new ArrayList<>()));
            userService.saveUser(new User(null, "FrankDinner","Frank", "12345", new ArrayList<>()));
            userService.saveUser(new User(null, "JaysDinner","Jay", "12345", new ArrayList<>()));

            userService.addRoleToUser("Jon", "ROLE_USER");
            userService.addRoleToUser("Will", "ROLE_MANAGER");
            userService.addRoleToUser("Frank", "ROLE_USER");
            userService.addRoleToUser("Jay", "ROLE_ADMIN");
            userService.addRoleToUser("Jay", "ROLE_SUPER_ADMIN");

        };
    }
}