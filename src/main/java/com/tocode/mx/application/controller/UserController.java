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
* Nombre de archivo: UserController.java 
* Autor: salvgonz 
* Fecha de creación: Mar 15, 2021 
*/

package com.tocode.mx.application.controller;

import com.tocode.mx.application.service.AwsCognitoService;
import com.tocode.mx.model.CognitoUser;

import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;



/**
 * The Class UserController.
 */
@RestController

/** The Constant log. */
@Slf4j
public class UserController {
  
  /** The cognito. */
  private AwsCognitoService cognito;
  
  /**
   * Instantiates a new user controller.
   *
   * @param cognitoService the cognito service
   */
  public UserController(AwsCognitoService cognitoService) {
    this.cognito = cognitoService;
  }  

  /**
   * Gets the user.
   *
   * @param userId the user id
   * @param the authorization jwt
   * @return the user
   */
  @GetMapping(value = "/api/users/{userId}")
  public ResponseEntity<CognitoUser> getUser(
      @PathVariable(value = "userId") Integer userId, 
      @RequestHeader(value = "Authorization", required = true) String authorization) {
    
    log.info("userId: [{}]", userId);
    log.info("Authorization: [{}]", authorization);
    
    CognitoUser user = userId == 0 ? cognito.validateToken(authorization) : null;
    log.info(user.toString());
    
    return new ResponseEntity<>(user, HttpStatus.OK);
  }
}
