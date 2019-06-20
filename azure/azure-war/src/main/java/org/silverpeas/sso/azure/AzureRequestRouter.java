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

package org.silverpeas.sso.azure;

import com.microsoft.aad.adal4j.AuthenticationResult;
import org.silverpeas.core.web.sso.SilverpeasSsoHttpServlet;
import org.silverpeas.core.web.sso.SilverpeasSsoPrincipal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static java.text.MessageFormat.format;
import static org.silverpeas.sso.azure.AzureLogger.getLogSessionId;
import static org.silverpeas.sso.azure.AzureLogger.logger;
import static org.silverpeas.sso.azure.settings.AzureSettings.getSilverpeasDomainId;

/**
 * @author silveryocha
 */
public class AzureRequestRouter extends SilverpeasSsoHttpServlet {

  @Override
  protected SilverpeasSsoPrincipal computeSsoPrincipal(final HttpServletRequest request,
      final HttpServletResponse response) {
    final AuthenticationResult result = AuthHelper.getAuthSessionObject(request);
    if (response.getStatus() == 500) {
      logger().debug(() -> format("Technical azure error for session {0}.", getLogSessionId(request)));
    } else if (result == null) {
      logger().debug(() -> format("No azure principal for session {0}.", getLogSessionId(request)));
    } else {
      return new SilverpeasSsoPrincipal() {
        @Override
        public String getDomainId() {
          return getSilverpeasDomainId();
        }

        @Override
        public String getName() {
          return result.getUserInfo().getDisplayableId();
        }
      };
    }
    return null;
  }
}
