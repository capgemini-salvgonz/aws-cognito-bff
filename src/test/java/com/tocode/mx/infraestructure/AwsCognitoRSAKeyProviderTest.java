package com.tocode.mx.infraestructure;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.junit.Test;

public class AwsCognitoRSAKeyProviderTest {

  @Test
  public void tokenVefier() {
    String aws_cognito_region = "us-east-2";
    String aws_user_pool_id = "us-east-2_";
    RSAKeyProvider keyProvider = new AwsCognitoRSAKeyProvider(aws_cognito_region, aws_user_pool_id);
    
    Algorithm algorithm = Algorithm.RSA256(keyProvider);
    JWTVerifier jwtVerifier = JWT.require(algorithm).build();

    String token = "eyJraWQiOiJmb245WmViRnJHa0xHenFldnRERDhqc2ppZEFmZEZ6MWN2cHl";    
    DecodedJWT jwt = jwtVerifier.verify(token);
    
    System.out.println(jwt.getClaims().get("nickname"));
    System.out.println(jwt.getClaims().get("phone_number"));
    System.out.println(jwt.getClaims().get("cognito:username"));
    System.out.println(jwt.getClaims().get("email"));
  }
}



