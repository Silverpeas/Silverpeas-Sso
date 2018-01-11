/*
 * Copyright (C) 2000 - 2018 Silverpeas
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

package org.silverpeas.sso.azure;

import com.microsoft.aad.adal4j.AuthenticationResult;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Map;

/**
 * @author silveryocha
 */
public final class AuthHelper {

  static final String PRINCIPAL_ATTRIBUTE_NAME = "silverpeas:sso:principal";

  private AuthHelper() {
  }

  static boolean isAuthenticated(HttpServletRequest request) {
    final HttpSession session = request.getSession(false);
    return session != null && session.getAttribute(PRINCIPAL_ATTRIBUTE_NAME) != null;
  }

  static void invalidateAuth(HttpServletRequest request) {
    final HttpSession session = request.getSession(false);
    if (session != null) {
      session.setAttribute(PRINCIPAL_ATTRIBUTE_NAME, null);
    }
  }

  static AuthenticationResult getAuthSessionObject(HttpServletRequest request) {
    final HttpSession session = request.getSession(false);
    return session != null
        ? (AuthenticationResult) session.getAttribute(PRINCIPAL_ATTRIBUTE_NAME)
        : null;
  }

  static boolean containsAuthenticationData(HttpServletRequest httpRequest) {
    Map<String, String[]> map = httpRequest.getParameterMap();
    return httpRequest.getMethod().equalsIgnoreCase("POST") &&
        (map.containsKey(AuthParameterNames.ERROR) ||
            map.containsKey(AuthParameterNames.ID_TOKEN) ||
            map.containsKey(AuthParameterNames.CODE));
  }

  static boolean isAuthenticationSuccessful(AuthenticationResponse authResponse) {
    return authResponse instanceof AuthenticationSuccessResponse;
  }
}
