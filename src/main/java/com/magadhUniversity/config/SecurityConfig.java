package com.magadhUniversity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeHttpRequests((requests) -> requests
                        // Allow access to static resources
                        .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()
                        // Specify URL access rules for different roles
                        .requestMatchers("/students/**").hasAnyRole("ADMIN", "EMPLOYEE")
                        .requestMatchers("/employees/**").hasRole("ADMIN")
                        .requestMatchers("/employees/attendance/**").hasAnyRole("ADMIN", "EMPLOYEE")
                        .requestMatchers("/attendance/**").hasRole("EMPLOYEE")
                        .requestMatchers("/student-marks/**").hasAnyRole("ADMIN", "EMPLOYEE")
                        .requestMatchers("/subjects/**").hasRole("ADMIN")
                        .requestMatchers("/mark_attendance").authenticated()
                        // Any other request needs to be authenticated
                        .anyRequest().authenticated()
                )
                .formLogin()
                .loginPage("/login").permitAll()  // Public login page
                .defaultSuccessUrl("/home", true)  // Default landing page after login
                .and()
                .logout().permitAll()
                .and()
                .exceptionHandling()
                .accessDeniedPage("/access-denied");  // Redirect to a custom access denied page if access is denied

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
