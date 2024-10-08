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

import org.ietf.jgss.*;
import org.silverpeas.sso.kerberos.spnego.KerberosSpnegoFilter.Constants;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import static org.silverpeas.sso.kerberos.KerberosLogger.logger;

/**
 * This is a Utility Class that can be used for finer grained control
 * over message integrity, confidentiality and mutual authentication.
 * <p/>
 * <p>
 * This Class is exposed for developers who want to implement a custom
 * HTTP client.
 * </p>
 * <p/>
 * <p>
 * Take a look at the {@link SpnegoHttpURLConnection} class and the
 * {@link KerberosSpnegoFilter} class before attempting to implement your
 * own HTTP client.
 * </p>
 * <p/>
 * <p>For more example usage, see the documentation at
 * <a href="http://spnego.sourceforge.net" target="_blank">http://spnego.sourceforge.net</a>
 * </p>
 * @author Darwin V. Felix
 */
public final class SpnegoProvider {

  /**
   * Factory for GSS-API mechanism.
   */
  static final GSSManager MANAGER = GSSManager.getInstance(); // NOPMD

  /**
   * GSS-API mechanism "1.3.6.1.5.5.2".
   */
  static final Oid SPNEGO_OID = SpnegoProvider.getOid(); // NOPMD

  /*
   * This is a utility class (not a Singleton).
   */
  private SpnegoProvider() {
    // default private
  }

  /**
   * Returns the {@link SpnegoAuthScheme} mechanism used to authenticate
   * the request.
   * <p/>
   * <p>
   * This method may return null in which case you must check the HTTP
   * Status Code to determine if additional processing is required.
   * <br />
   * For example, if req. did not contain the SpnegoConstants.AUTHZ_HEADER,
   * the HTTP Status Code SC_UNAUTHORIZED will be set and the client must
   * send authentication information on the next request.
   * </p>
   * @param req servlet request
   * @param resp servlet response
   * @param basicSupported pass true to offer/allow BASIC Authentication
   * @param promptIfNtlm pass true ntlm request should be downgraded
   * @param realm should be the realm the server used to pre-authenticate
   * @return null if negotiation needs to continue or failed
   * @throws IOException if an IO error occurs
   */
  static SpnegoAuthScheme negotiate(final HttpServletRequest req,
      final SpnegoHttpServletResponse resp, final boolean basicSupported,
      final boolean promptIfNtlm, final String realm) throws IOException {

    final SpnegoAuthScheme scheme =
        SpnegoProvider.getAuthScheme(req.getHeader(Constants.AUTHZ_HEADER));

    if (null == scheme || scheme.getToken().length == 0) {
      logger().debug("Header Token was NULL");
      resp.setHeader(Constants.AUTHN_HEADER, Constants.NEGOTIATE_HEADER);

      if (basicSupported) {
        resp.addHeader(Constants.AUTHN_HEADER, Constants.BASIC_HEADER + " realm=\"" + realm + '\"');
      } else {
        logger().debug("Basic NOT offered: Not Enabled or SSL Required.");
      }

      resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED, true);

      return null;

    }

    // assert
    if (scheme.isNtlmToken()) {
      logger().warn("Downgrade NTLM request to Basic Auth.");

      if (resp.isStatusSet()) {
        throw new IllegalStateException("HTTP Status already set.");
      }

      if (basicSupported && promptIfNtlm) {
        resp.setHeader(Constants.AUTHN_HEADER, Constants.BASIC_HEADER + " realm=\"" + realm + '\"');
      } else {
        // TODO : decode/decrypt NTLM token and return a new SpnegoAuthScheme
        // of type "Basic" where the token value is a base64 encoded
        // username + ":" + password string
        throw new UnsupportedOperationException("NTLM specified. Downgraded to " +
            "Basic Auth (and/or SSL) but downgrade not supported.");
      }

      resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED, true);

      return null;
    }

    return scheme;
  }

  /**
   * Returns the GSS-API interface for creating a security context.
   * @param subject the person to be authenticated
   * @return GSSCredential to be used for creating a security context.
   * @throws PrivilegedActionException if a disallowed action is performed
   */
  public static GSSCredential getClientCredential(final Subject subject)
      throws PrivilegedActionException {

    final PrivilegedExceptionAction<GSSCredential> action =
        () -> MANAGER.createCredential(null, GSSCredential.DEFAULT_LIFETIME,
            SpnegoProvider.SPNEGO_OID, GSSCredential.INITIATE_ONLY);

    return Subject.doAs(subject, action);
  }

  /**
   * Returns a GSSContext to be used by custom clients to set
   * data integrity requirements, confidentiality and if mutual
   * authentication is required.
   * @param creds credentials of the person to be authenticated
   * @param url HTTP address of server (used for constructing a {@link GSSName}).
   * @return GSSContext
   * @throws GSSException if the SSO negotiation fails
   */
  public static GSSContext getGSSContext(final GSSCredential creds, final URL url)
      throws GSSException {

    return MANAGER
        .createContext(SpnegoProvider.getServerName(url), SpnegoProvider.SPNEGO_OID, creds,
            GSSContext.DEFAULT_LIFETIME);
  }

  /**
   * Returns the {@link SpnegoAuthScheme} or null if header is missing.
   * <p/>
   * <p>
   * Throws UnsupportedOperationException if header is NOT Negotiate
   * or Basic.
   * </p>
   * @param header ex. Negotiate or Basic
   * @return null if header missing/null else the auth scheme
   */
  static SpnegoAuthScheme getAuthScheme(final String header) {

    if (null == header || header.isEmpty()) {
      logger().debug("authorization header was missing/null");
      return null;

    } else if (header.startsWith(Constants.NEGOTIATE_HEADER)) {
      final String token = header.substring(Constants.NEGOTIATE_HEADER.length() + 1);
      return new SpnegoAuthScheme(Constants.NEGOTIATE_HEADER, token);

    } else if (header.startsWith(Constants.BASIC_HEADER)) {
      final String token = header.substring(Constants.BASIC_HEADER.length() + 1);
      return new SpnegoAuthScheme(Constants.BASIC_HEADER, token);

    } else {
      throw new UnsupportedOperationException("Negotiate or Basic Only:" + header);
    }
  }

  /**
   * Returns the Universal Object Identifier representation of
   * the SPNEGO mechanism.
   * @return Object Identifier of the GSS-API mechanism
   */
  private static Oid getOid() {
    Oid oid = null;
    try {
      oid = new Oid("1.3.6.1.5.5.2");
    } catch (GSSException gsse) {
      logger().error("Unable to create OID 1.3.6.1.5.5.2 !", gsse);
    }
    return oid;
  }

  /**
   * Returns the {@link GSSCredential} the server uses for pre-authentication.
   * @param subject account server uses for pre-authentication
   * @return credential that allows server to authenticate clients
   * @throws PrivilegedActionException if the action isn't allowed
   */
  static GSSCredential getServerCredential(final Subject subject) throws PrivilegedActionException {

    final PrivilegedExceptionAction<GSSCredential> action =
        () -> MANAGER.createCredential(null, GSSCredential.INDEFINITE_LIFETIME,
            SpnegoProvider.SPNEGO_OID, GSSCredential.ACCEPT_ONLY);
    return Subject.doAs(subject, action);
  }

  /**
   * Returns the {@link GSSName} constructed out of the passed-in
   * URL object.
   * @param url HTTP address of server
   * @return GSSName of URL.
   * @throws GSSException if the SSO negotiation fails.
   */
  static GSSName getServerName(final URL url) throws GSSException {
    return MANAGER.createName("HTTP@" + url.getHost(), GSSName.NT_HOSTBASED_SERVICE,
        SpnegoProvider.SPNEGO_OID);
  }

  /**
   * Used by the BASIC Auth mechanism for establishing a LoginContext
   * to authenticate a client/caller/request.
   * @param username client username
   * @param password client password
   * @return CallbackHandler to be used for establishing a LoginContext
   */
  public static CallbackHandler getUsernamePasswordHandler(final String username,
      final String password) {

    logger().debug("username=" + username + "; password=" + password.hashCode());

    return callback -> {
      for (int i = 0; i < callback.length; i++) {
        if (callback[i] instanceof NameCallback) {
          final NameCallback nameCallback = (NameCallback) callback[i];
          nameCallback.setName(username);
        } else if (callback[i] instanceof PasswordCallback) {
          final PasswordCallback passCallback = (PasswordCallback) callback[i];
          passCallback.setPassword(password.toCharArray());
        } else {
          logger().warn(
              "Unsupported Callback i=" + i + "; class=" + callback[i].getClass().getName());
        }
      }
    };
  }
}
