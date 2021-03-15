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
* Nombre de archivo: AwsCognitoRSAKeyProvider.java 
* Autor: salvgonz 
* Fecha de creación: Mar 15, 2021 
*/

package com.tocode.mx.infraestructure;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


/**
 * The Class AwsCognitoRSAKeyProvider.
 */
public class AwsCognitoRSAKeyProvider implements RSAKeyProvider {

  /** The aws kid store url. */
  private final URL aws_kid_store_url;

  /**
   * Instantiates a new aws cognito RSA key provider.
   *
   * @param aws_cognito_region the aws cognito region
   * @param aws_user_pools_id the aws user pools id
   */
  public AwsCognitoRSAKeyProvider(String aws_cognito_region, String aws_user_pools_id) {

    String url = String.format("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json",
        aws_cognito_region, aws_user_pools_id);
    try {
      this.aws_kid_store_url = new URL(url);
    } catch (MalformedURLException e) {
      throw new RuntimeException(String.format("Invalid URL provided, URL=%s", url));
    }
  }

  /**
   * Gets the public key by id.
   *
   * @param keyId the key id
   * @return the public key by id
   */
  @Override
  public RSAPublicKey getPublicKeyById(String keyId) {
    try {
      JwkProvider provider = new JwkProviderBuilder(aws_kid_store_url).build();
      Jwk jwk = provider.get(keyId);
      return (RSAPublicKey) jwk.getPublicKey();
    } catch (Exception e) {
      throw new RuntimeException(e.getMessage(), e);
    }
  }

  /**
   * Gets the private key.
   *
   * @return the private key
   */
  @Override
  public RSAPrivateKey getPrivateKey() {
    return null;
  }

  /**
   * Gets the private key id.
   *
   * @return the private key id
   */
  @Override
  public String getPrivateKeyId() {
    return null;
  }

}
