/*
 * Copyright (C) 2000 - 2026 Silverpeas
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

import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.Map;

/**
 * @author silveryocha
 */
public final class AuthHelper {

  static final String PRINCIPAL_ATTRIBUTE_NAME = "silverpeas:sso:principal";
  static final String TOKEN_CACHE_ATTRIBUTE_NAME = "silverpeas:sso:tokenCache";

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

  static IAuthenticationResult getAuthSessionObject(HttpServletRequest request) {
    final HttpSession session = request.getSession(false);
    return session != null
        ? (IAuthenticationResult) session.getAttribute(PRINCIPAL_ATTRIBUTE_NAME)
        : null;
  }

  static String getTokenCache(HttpServletRequest request) {
    final HttpSession session = request.getSession(false);
    return session != null ? (String) session.getAttribute(TOKEN_CACHE_ATTRIBUTE_NAME) : null;
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
