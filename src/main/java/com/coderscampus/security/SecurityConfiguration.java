package com.coderscampus.security;

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
  
  
  //sets up in memory admin user
  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth
      .inMemoryAuthentication()
      .passwordEncoder(passwordEncoder)
      .withUser("c@email.com")
      .password("$2a$10$FuLmwiTg0mUK5dcijbndmuIHNvxTtZA9jsPBP7DR4SLHOMLEHdV9G")
      .roles("USER", "ADMIN");
  }
  
 //sets up access for admin user
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .csrf().disable()
      .authorizeRequests()
        .antMatchers("/admin/**").hasAnyRole("ADMIN")
        .anyRequest().hasAnyRole("USER").and()
      .formLogin()
        .loginPage("/login")
        .defaultSuccessUrl("/dashboard")
        .permitAll();
  }
 
  
//allows access to the resources and static folders
  
  @Override
  public void configure(WebSecurity web) {
      web.ignoring().antMatchers("/resources/**", "/static/**");
  }
}
