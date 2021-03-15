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
* Nombre de archivo: CognitoUser.java 
* Autor: salvgonz 
* Fecha de creación: Mar 15, 2021 
*/

package com.tocode.mx.model;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * The Class CognitoUser.
 */
@Getter
@Setter
@ToString
public class CognitoUser {

  /** The cognit user name. */
  private String cognitoUserName;

  /** The nick name. */
  private String nickName;

  /** The phone number. */
  private String phoneNumber;

  /** The email. */
  private String email;
}
