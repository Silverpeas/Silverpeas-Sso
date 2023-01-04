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

package org.silverpeas.sso.kerberos;

import org.silverpeas.core.SilverpeasExceptionMessages.LightExceptionMessage;
import org.silverpeas.core.admin.user.model.User;
import org.silverpeas.core.web.sso.SilverpeasSsoHttpServlet;
import org.silverpeas.core.web.sso.SilverpeasSsoPrincipal;
import org.silverpeas.sso.kerberos.spnego.SpnegoManager;
import org.silverpeas.sso.kerberos.spnego.SpnegoPrincipal;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;
import java.io.IOException;

import static java.text.MessageFormat.format;
import static java.util.Optional.ofNullable;
import static org.silverpeas.sso.kerberos.KerberosLogger.getLogSessionId;
import static org.silverpeas.sso.kerberos.KerberosLogger.logger;
import static org.silverpeas.sso.kerberos.settings.KerberosSettings.getSilverpeasDomainId;

/**
 * @author silveryocha
 */
public class KerberosRequestRouter extends SilverpeasSsoHttpServlet {
  private static final long serialVersionUID = 2833617793563756703L;

  @Override
  public void doPost(final HttpServletRequest request, final HttpServletResponse response) {
    try {
      if (request.getRequestURI().matches("^.+/nego/?$")) {
        if (request.getParameter("pre-auth") != null) {
          response.setHeader("Content-Type", MediaType.TEXT_PLAIN + "; charset=UTF-8");
          response.flushBuffer();
        } else {
          super.doPost(request, response);
        }
      } else {
        final String urlToDispatch;
        if (request.getRequestURI().matches("^.+/reload$")) {
          if (ofNullable(User.getCurrentRequester()).filter(User::isAccessAdmin).isPresent()) {
            SpnegoManager.get().reload();
          }
          urlToDispatch = "/Login";
        } else {
          urlToDispatch = "/kerberos-pre-auth.jsp";
        }
        RequestDispatcher requestDispatcher = getServletConfig().getServletContext().getRequestDispatcher(urlToDispatch);
        requestDispatcher.forward(request, response);
      }
    } catch (ServletException | IOException e) {
      logger().error(new LightExceptionMessage(this, e).singleLineWith("Error while performing SSO authentication"));
      response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  @Override
  protected SilverpeasSsoPrincipal computeSsoPrincipal(final HttpServletRequest request,
      final HttpServletResponse response) {
    if (request.getUserPrincipal() instanceof SpnegoPrincipal) {
      return new SilverpeasSsoPrincipal() {
        @Override
        public String getDomainId() {
          return getSilverpeasDomainId();
        }

        @Override
        public String getName() {
          return request.getRemoteUser();
        }
      };
    } else {
      logger().debug(() -> format("No Kerberos/SPNEGO principal for session {0}.", getLogSessionId(request)));
    }
    return null;
  }
}
