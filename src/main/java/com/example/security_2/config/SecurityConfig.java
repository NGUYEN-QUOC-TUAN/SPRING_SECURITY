package com.example.security_2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    // authentication
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        UserDetails admin = User.withUsername("tuannq")
                .password(encoder.encode("ph20022"))
                .roles("ADMIN")
                .build();
        UserDetails user = User.withUsername("phongtt3222")
                .password(encoder.encode("123"))
                .roles("USER")
                .build();
        UserDetails user2 = User.withUsername("phongtt32")
                .password(encoder.encode("123"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(admin, user, user2);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers("/hello").permitAll() // với endpoint /hello thì sẽ được cho qua
                .and()
                .authorizeHttpRequests()
                .requestMatchers("/customer/**").authenticated() // với endpoint /customer/** sẽ yêu cầu authenticate
                .and().formLogin() // trả về page login nếu chưa authenticate
                .and().build();
    }

}
