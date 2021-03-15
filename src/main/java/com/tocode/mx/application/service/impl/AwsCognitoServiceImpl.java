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
* Nombre de archivo: AwsCognitoServiceImpl.java 
* Autor: salvgonz 
* Fecha de creación: Mar 15, 2021 
*/

package com.tocode.mx.application.service.impl;

import com.tocode.mx.application.service.AwsCognitoService;
import com.tocode.mx.infraestructure.AwsCognitoRSAKeyProvider;
import com.tocode.mx.model.CognitoUser;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * The Class AwsCognitoServiceImpl.
 */
@Service
public class AwsCognitoServiceImpl implements AwsCognitoService {

  /** The key provider. */
  private RSAKeyProvider keyProvider;

  /**
   * Instantiates a new aws cognito service impl.
   */
  public AwsCognitoServiceImpl(
      @Value("${com.tocode.mx.cognito.userPoolId}") String userPoolId,
      @Value("${com.tocode.mx.cognito.awsRegion}")  String awsRegion ) {
    
    keyProvider = new AwsCognitoRSAKeyProvider(awsRegion, userPoolId);
  }

  /**
   * Validate token.
   *
   * @param cognitoJwt the cognito jwt
   * @return the cognito user
   */
  @Override
  public CognitoUser validateToken(String cognitoJwt) {
    
    cognitoJwt = cognitoJwt.startsWith("Bearer ") ? cognitoJwt.split(" ")[1] : cognitoJwt;
    
    Algorithm algorithm = Algorithm.RSA256(keyProvider);
    JWTVerifier jwtVerifier = JWT.require(algorithm).build();
    DecodedJWT jwt = jwtVerifier.verify(cognitoJwt);
    
    CognitoUser user = new CognitoUser();
    
    user.setNickName(jwt.getClaims().get("nickname").asString());
    user.setPhoneNumber(jwt.getClaims().get("phone_number").asString());
    user.setCognitoUserName(jwt.getClaims().get("cognito:username").asString());
    user.setEmail(jwt.getClaims().get("email").asString());
    
    return user;
  }

}
