package com.frugalfareadmin.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
  
  @Autowired
  private PasswordEncoder passwordEncoder;
  
  @Bean
  public PasswordEncoder passwordEncoder () {
    return new BCryptPasswordEncoder();
  }
  
  
  //Sets up an in memory admin user with encrypted password.
  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth
      .inMemoryAuthentication()
      .passwordEncoder(passwordEncoder)
      .withUser("shawn@gmail.com")
      .password("$2a$10$2mvsOcZd4aK6oNg119ERGOw1HnpRo3FFoyKUYgpq.6gYf1wRoyMdC")
      .roles("USER", "ADMIN");
  }
  
 //Sets up access for admin user.
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .csrf().disable()
      .authorizeRequests()
      .antMatchers("/resources/**", "/static/**").permitAll()
        .antMatchers("/admin/**").hasAnyRole("ADMIN")
        .anyRequest().hasAnyRole("USER").and()
      .formLogin()
        .loginPage("/login")
        .defaultSuccessUrl("/dashboard")
        .permitAll();
  }
 
  
   //Allow views to access to the resources and static folders.
  @Override
  public void configure(WebSecurity web) throws Exception {
      web
              .ignoring()
              .antMatchers("/resources/**", "/static/**", "/css/**", "/js/**", "/images/**", "/icon/**");
  }
}
