/*
*                     GNU GENERAL PUBLIC LICENSE
*                        Version 3, 29 June 2007
* 
*  Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
*  Everyone is permitted to copy and distribute verbatim copies
*  of this license document, but changing it is not allowed.
* 
*                             Preamble
* 
*   The GNU General Public License is a free, copyleft license for
* software and other kinds of works.
* 
*   The licenses for most software and other practical works are designed
* to take away your freedom to share and change the works.  By contrast,
* the GNU General Public License is intended to guarantee your freedom to
* share and change all versions of a program--to make sure it remains free
* software for all its users.  We, the Free Software Foundation, use the
* GNU General Public License for most of our software; it applies also to
* any other work released this way by its authors.  You can apply it to
* your programs, too.
*
* Nombre de archivo: SecurityConfiguration.java 
* Autor: salvgonz 
* Fecha de creación: Mar 17, 2021 
*/


package com.tocode.mx.infraestructure.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;



/**
 * The Class SecurityConfiguration.
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter { 
  
  /** The filter security. */
  @Autowired
  private FilterSecurity filterSecurity;
  
  /**
   * Configure.
   *
   * @param  the http security
   * @throws Exception 
   */
  @Override
  protected void configure(HttpSecurity httpSecurity) throws Exception {

      httpSecurity.sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .cors().and()
        .csrf().disable()
        .authorizeRequests()
        .anyRequest().authenticated();
      
      httpSecurity.addFilterBefore(filterSecurity, UsernamePasswordAuthenticationFilter.class);
  }
  
  /**
   * Cors configuration source.
   *
   * @return the cors configuration source
   */
  @Bean
  CorsConfigurationSource corsConfigurationSource() {
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
      return source;
  }
}
