/*
 * Copyright (C) 2000 - 2019 Silverpeas
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * As a special exception to the terms and conditions of version 3.0 of
 * the GPL, you may redistribute this Program in connection with Free/Libre
 * Open Source Software ("FLOSS") applications as described in Silverpeas's
 * FLOSS exception.  You should have received a copy of the text describing
 * the FLOSS exception, and it is also available here:
 * "https://www.silverpeas.org/legal/floss_exception.html"
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.silverpeas.sso.kerberos.spnego;

import org.silverpeas.sso.kerberos.spnego.KerberosSpnegoFilter.Constants;

/**
 * Example schemes are "Negotiate" and "Basic".
 * <p/>
 * <p>See examples and tutorials at
 * <a href="http://spnego.sourceforge.net" target="_blank">http://spnego.sourceforge.net</a>
 * </p>
 * @author Darwin V. Felix
 */
final class SpnegoAuthScheme {

  /**
   * Zero length byte array.
   */
  private static final transient byte[] EMPTY_BYTE_ARRAY = new byte[0];

  /**
   * HTTP (Request) "Authorization" Header scheme.
   */
  private final transient String scheme;

  /**
   * HTTP (Request) scheme token.
   */
  private final transient String token;

  /**
   * true if Basic Auth scheme.
   */
  private final transient boolean basicScheme;

  /**
   * true if Negotiate scheme.
   */
  private final transient boolean negotiateScheme;

  /**
   * true if NTLM token.
   */
  private final transient boolean ntlm;

  /**
   * @param authScheme
   * @param authToken
   */
  public SpnegoAuthScheme(final String authScheme, final String authToken) {
    this.scheme = authScheme;
    this.token = authToken;

    if (null == authToken || authToken.isEmpty()) {
      this.ntlm = false;
    } else {
      this.ntlm = authToken.startsWith(Constants.NTLM_PROLOG);
    }

    this.negotiateScheme = Constants.NEGOTIATE_HEADER.equalsIgnoreCase(authScheme);
    this.basicScheme = Constants.BASIC_HEADER.equalsIgnoreCase(authScheme);
  }

  /**
   * Returns true if this SpnegoAuthScheme is of type "Basic".
   * @return true if Basic Auth scheme
   */
  boolean isBasicScheme() {
    return this.basicScheme;
  }

  /**
   * Returns true if this SpnegoAuthScheme is of type "Negotiate".
   * @return true if Negotiate scheme
   */
  boolean isNegotiateScheme() {
    return this.negotiateScheme;
  }

  /**
   * Returns true if NTLM.
   * @return true if Servlet Filter received NTLM token
   */
  boolean isNtlmToken() {
    return this.ntlm;
  }

  /**
   * Returns HTTP Authorization scheme.
   * @return "Negotiate" or "Basic"
   */
  public String getScheme() {
    return this.scheme;
  }

  /**
   * Returns a copy of byte[].
   * @return copy of token
   */
  public byte[] getToken() {
    return (null == this.token) ? EMPTY_BYTE_ARRAY : Base64.decode(this.token);
  }
}
