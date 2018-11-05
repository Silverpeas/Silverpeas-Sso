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

package org.silverpeas.sso.saml;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Optional;

import static java.util.Optional.empty;
import static java.util.Optional.ofNullable;

/**
 * @author silveryocha
 */
public final class SamlAuthHelper {

  private static final String AUTHENTICATION_REDIRECT = "saml:silverpeas:sso:principal";
  private static final String PRINCIPAL_ATTRIBUTE_NAME = "saml:silverpeas:sso:principal";

  private SamlAuthHelper() {
  }

  static boolean isAuthenticated(HttpServletRequest request) {
    final HttpSession session = request.getSession(false);
    return session != null && session.getAttribute(PRINCIPAL_ATTRIBUTE_NAME) != null;
  }

  static void invalidateAuth(HttpServletRequest request) {
    final HttpSession session = request.getSession(false);
    if (session != null) {
      session.removeAttribute(AUTHENTICATION_REDIRECT);
      session.removeAttribute(PRINCIPAL_ATTRIBUTE_NAME);
    }
  }

  static void setSessionPrincipal(HttpServletRequest httpRequest, String principal) {
    httpRequest.getSession().setAttribute(PRINCIPAL_ATTRIBUTE_NAME, principal);
  }

  static Optional<String> getAuthSessionPrincipal(HttpServletRequest request) {
    final HttpSession session = request.getSession(false);
    return session != null
        ? ofNullable((String) session.getAttribute(PRINCIPAL_ATTRIBUTE_NAME))
        : empty();
  }
}
