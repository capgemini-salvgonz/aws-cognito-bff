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
* Nombre de archivo: FilterSecurity.java 
* Autor: salvgonz 
* Fecha de creación: Mar 17, 2021 
*/

package com.tocode.mx.infraestructure.security;

import com.tocode.mx.application.dto.CognitoUser;
import com.tocode.mx.application.service.AwsCognitoService;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;



/**
 * The Class FilterSecurity.
 */
@Component
@Slf4j
public class FilterSecurity extends OncePerRequestFilter {

  /** The Constant AUTHORIZATION_HEADER. */
  private static final String AUTHORIZATION_HEADER = "Authorization";
  
  /** The Constant TOKEN_NOT_FOUND. */
  private static final String TOKEN_NOT_FOUND = "Token not found";

  /** The Cognito service. */
  @Autowired
  private AwsCognitoService cognitoService;

  /**
   * Do filter internal.
   *
   * @param request the request
   * @param response the response
   * @param filterChain the filter chain
   * @throws ServletException the servlet exception
   * @throws IOException Signals that an I/O exception has occurred.
   */
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    String tokenId = request.getHeader(AUTHORIZATION_HEADER);

    if (tokenId == null) {
      filterChain.doFilter(request, response);
      log.info(TOKEN_NOT_FOUND);
    }

    CognitoUser user = cognitoService.validateToken(tokenId);
    log.info(tokenId);
    log.info("User [{}]", user.getNickName());
    SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
        user.getNickName(), user.getCognitoUserName(), new ArrayList<>()));
    filterChain.doFilter(request, response);
  }
}
