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
* Nombre de archivo: GlobalExceptionHandler.java 
* Autor: salvgonz 
* Fecha de creación: Mar 16, 2021 
*/

package com.tocode.mx.infraestructure.exception;

import com.auth0.jwt.exceptions.TokenExpiredException;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;


/**
 * The Class GlobalExceptionHandler.
 */
@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

  /**
   * Catch token expired exception.
   *
   * @param ex the ex
   * @param request the request
   * @return the response entity
   */
  @ExceptionHandler(value = {TokenExpiredException.class, 
      InvalidBearerTokenException.class, JwtValidationException.class})
  public ResponseEntity<ErrorResponse> catchTokenExpiredException(Exception ex,
      WebRequest request) {
    log.info(ex.getMessage());

    ErrorResponse response = new ErrorResponse();
    response.setCode(500);
    response.setMessage(ex.getMessage());
    response.setType("security");
    response.setErrorCode(100);
    response.setMoreInfo("Token expired");

    return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
  }
}
