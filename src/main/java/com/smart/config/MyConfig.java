package com.smart.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableMethodSecurity
public class MyConfig{
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	
	@Bean
	public UserDetailsService getUserDetailsService() {
		
//		UserDetails user= User.withUsername("sushma@gmail.com").password(passwordEncoder().encode("sushma10")).roles("USER").build();
//		UserDetails user1= User.withUsername("shreya@gmail.com").password(passwordEncoder().encode("0309")).roles("USER").build();
	
//		InMemoryUserDetailsManager inMemoryUserDetailsManager = new InMemoryUserDetailsManager(user,user1);
//		
//		return inMemoryUserDetailsManager;
		
		return new UserDetailsServiceImpl();
	}
	
	@Bean
	public SecurityFilterChain securityChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
        
        .authorizeHttpRequests(auth->{auth.requestMatchers("/admin/**").hasRole("ADMIN")
        .requestMatchers("/user/**").hasRole("USER").requestMatchers("/**").permitAll();})
    
        .formLogin(login->login.loginPage("/signin")
        		               .loginProcessingUrl("/dologin")
        		               .defaultSuccessUrl("/user/index"));
        
         return http.build();
    }
	
	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider daoAuthenticationProvider=new DaoAuthenticationProvider();
		
		daoAuthenticationProvider.setUserDetailsService(this.getUserDetailsService());
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
		
		return daoAuthenticationProvider;
	}

}