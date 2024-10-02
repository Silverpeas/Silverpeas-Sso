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

import org.ietf.jgss.GSSException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileNotFoundException;
import java.io.IOException;

import static org.silverpeas.sso.kerberos.KerberosLogger.logger;

/**
 * Http Servlet Filter that provides <a
 * href="http://en.wikipedia.org/wiki/SPNEGO" target="_blank">SPNEGO</a> authentication.
 * It allows servlet containers like Tomcat and JBoss to transparently/silently
 * authenticate HTTP clients like Microsoft Internet Explorer (MSIE).
 * <p/>
 * <p>
 * This feature in MSIE is sometimes referred to as single sign-on and/or
 * Integrated Windows Authentication. In general, there are at least two
 * authentication mechanisms that allow an HTTP server and an HTTP client
 * to achieve single sign-on: <b>NTLM</b> and <b>Kerberos/SPNEGO</b>.
 * </p>
 * <p/>
 * <p>
 * <b>NTLM</b><br />
 * MSIE has the ability to negotiate NTLM password hashes over an HTTP session
 * using Base 64 encoded NTLMSSP messages. This is a staple feature of Microsoft's
 * Internet Information Server (IIS). Open source libraries exists (ie. jCIFS) that
 * provide NTLM-based authentication capabilities to Servlet Containers. jCIFS uses
 * NTLM and Microsoft's Active Directory (AD) to authenticate MSIE clients.
 * </p>
 * <p/>
 * <p>
 * <b>{@code SpnegoHttpFilter} does NOT support NTLM (tokens).</b>
 * </p>
 * <p/>
 * <p>
 * <b>Kerberos/SPNEGO</b><br />
 * Kerberos is an authentication protocol that is implemented in AD. The protocol
 * does not negotiate passwords between a client and a server but rather uses tokens
 * to securely prove/authenticate to one another over an un-secure network.
 * </p>
 * <p/>
 * <p>
 * <b><code>SpnegoHttpFilter</code> does support Kerberos but through the
 * pseudo-mechanism <code>SPNEGO</code></b>.
 * <ul>
 * <li><a href="http://en.wikipedia.org/wiki/SPNEGO" target="_blank">Wikipedia: SPNEGO</a></li>
 * <li><a href="http://www.ietf.org/rfc/rfc4178.txt" target="_blank">IETF RFC: 4178</a></li>
 * </ul>
 * </p>
 * <p/>
 * <p>
 * <b>Localhost Support</b><br />
 * The Kerberos protocol requires that a service must have a Principal Name (SPN)
 * specified. However, there are some use-cases where it may not be practical to
 * specify an SPN (ie. Tomcat running on a developer's machine). The DNS
 * http://localhost is supported but must be configured in the servlet filter's
 * init params in the web.xml file.
 * </p>
 * <p/>
 * <p><b>Modifying the web.xml file</b></p>
 * <p/>
 * <p>Here's an example configuration:</p>
 * <p/>
 * <p>
 * <pre><code>  &lt;filter&gt;
 *      &lt;filter-name&gt;SpnegoHttpFilter&lt;/filter-name&gt;
 *      &lt;filter-class&gt;org.silverpeas.spnego.SpnegoHttpFilter&lt;/filter-class&gt;
 * <p/>
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.allow.basic&lt;/param-name&gt;
 *          &lt;param-value&gt;true&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 * <p/>
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.allow.localhost&lt;/param-name&gt;
 *          &lt;param-value&gt;true&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 * <p/>
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.allow.unsecure.basic&lt;/param-name&gt;
 *          &lt;param-value&gt;true&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 * <p/>
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.login.client.module&lt;/param-name&gt;
 *          &lt;param-value&gt;spnego-client&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 * <p/>
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.krb5.conf&lt;/param-name&gt;
 *          &lt;param-value&gt;krb5.conf&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 * <p/>
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.login.conf&lt;/param-name&gt;
 *          &lt;param-value&gt;login.conf&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 * <p/>
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.preauth.username&lt;/param-name&gt;
 *          &lt;param-value&gt;Zeus&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 * <p/>
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.preauth.password&lt;/param-name&gt;
 *          &lt;param-value&gt;Zeus_Password&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 * <p/>
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.login.server.module&lt;/param-name&gt;
 *          &lt;param-value&gt;spnego-server&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 * <p/>
 *      &lt;init-param&gt;
 *          &lt;param-name&gt;spnego.prompt.ntlm&lt;/param-name&gt;
 *          &lt;param-value&gt;true&lt;/param-value&gt;
 *      &lt;/init-param&gt;
 *  &lt;/filter&gt;
 * </code></pre>
 * </p>
 * <p/>
 * <p><b>Example usage on web page</b></p>
 * <p/>
 * <p><pre>  &lt;html&gt;
 *  &lt;head&gt;
 *      &lt;title&gt;Hello SPNEGO Example&lt;/title&gt;
 *  &lt;/head&gt;
 *  &lt;body&gt;
 *  Hello &lt;%= request.getRemoteUser() %&gt; !
 *  &lt;/body&gt;
 *  &lt;/html&gt;
 *  </pre>
 * </p>
 * <p/>
 * <p>
 * Take a look at the <a href="http://spnego.sourceforge.net/reference_docs.html"
 * target="_blank">reference docs</a> for other configuration parameters.
 * </p>
 * <p/>
 * <p>See more usage examples at
 * <a href="http://spnego.sourceforge.net" target="_blank">http://spnego.sourceforge.net</a>
 * </p>
 * @author Darwin V. Felix
 */
public final class KerberosSpnegoFilter implements Filter {

  @Override
  public void init(final FilterConfig filterConfig) throws ServletException {
    try {
      // set some System properties
      final SpnegoFilterConfig config = SpnegoFilterConfig.getInstance(filterConfig);

      // pre-authenticate
      SpnegoManager.get().init(config);
    } catch (final FileNotFoundException e) {
      logger().error(e);
      throw new ServletException(e);
    }
  }

  @Override
  public void destroy() {
    SpnegoManager.get().logoutAuthenticator();
  }

  @Override
  public void doFilter(final ServletRequest request, final ServletResponse response,
      final FilterChain chain) throws IOException, ServletException {

    final HttpServletRequest httpRequest = (HttpServletRequest) request;
    if (httpRequest.getUserPrincipal() instanceof SpnegoPrincipal) {
      // Authentication is already performed
      chain.doFilter(httpRequest, response);
      return;
    }

    final SpnegoHttpServletResponse spnegoResponse = new SpnegoHttpServletResponse(
        (HttpServletResponse) response);

    // client/caller principal
    final SpnegoManager spnegoManager = SpnegoManager.get();
    final SpnegoPrincipal principal;
    try {
      principal = spnegoManager.getAuthenticator().authenticate(httpRequest, spnegoResponse);
    } catch (GSSException gsse) {
      logger().error("HTTP Authorization Header=" + httpRequest.getHeader(Constants.AUTHZ_HEADER));
      if (spnegoManager.isTypedRuntimeExceptionThrown()) {
        throw new SpnegoGSSException(gsse);
      }
      throw new ServletException(gsse);
    } catch (SpnegoUnauthenticatedException | SpnegoUnsupportedOperationException re) {
      throw re;
    } catch (RuntimeException re) {
      if (spnegoManager.isTypedRuntimeExceptionThrown()) {
        throw new SpnegoUnsupportedOperationException(re);
      }
      throw re;
    }

    // context/auth loop not yet complete
    if (spnegoResponse.isStatusSet()) {
      return;
    }

    // assert
    if (null == principal) {
      logger().error("Principal was null.");
      if (spnegoManager.isTypedRuntimeExceptionThrown()) {
        throw new SpnegoUnauthenticatedException("Principal was null.");
      }
      spnegoResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, true);
      return;
    }

    logger().debug("principal=" + principal);

    chain.doFilter(new SpnegoHttpServletRequest(httpRequest, principal), response);
  }

  /**
   * Defines constants and parameter names that are used in the
   * web.xml file, and HTTP request headers, etc.
   * <p/>
   * <p>
   * This class is primarily used internally or by implementers of
   * custom http clients and by {@link SpnegoFilterConfig}.
   * </p>
   */
  public static final class Constants {

    private Constants() {
      // default private
    }

    /**
     * Servlet init param name in web.xml <b>spnego.throw.typedRuntimeException</b>.
     * <p/>
     * <p>Set this value to <code>true</code> in web.xml if the filter
     * should throw typed runtime exception instead of ServletException.</p>
     * <p/>
     * <p>If exception have to be handled in the server application it
     * is recommended to set this parameter to <code>true</code>.</p>
     */
    public static final String THROW_TYPED_RUNTIME_EXCEPTION =
        "spnego.throw" + ".typedRuntimeException";

    /**
     * Servlet init param name in web.xml <b>spnego.allow.basic</b>.
     * <p/>
     * <p>Set this value to <code>true</code> in web.xml if the filter
     * should allow Basic Authentication.</p>
     * <p/>
     * <p>It is recommended that you only allow Basic Authentication
     * if you have clients that cannot perform Kerberos authentication.
     * Also, you should consider requiring SSL/TLS by setting
     * <code>spnego.allow.unsecure.basic</code> to <code>false</code>.</p>
     */
    public static final String ALLOW_BASIC = "spnego.allow.basic";

    /**
     * Servlet init param name in web.xml <b>spnego.allow.delegation</b>.
     * <p/>
     * <p>Set this value to <code>true</code> if server should support
     * credential delegation requests.</p>
     * <p/>
     * <p>Take a look at the {@link DelegateServletRequest} for more
     * information about other pre-requisites.</p>
     */
    public static final String ALLOW_DELEGATION = "spnego.allow.delegation";

    /**
     * Servlet init param name in web.xml <b>spnego.allow.localhost</b>.
     * <p/>
     * <p>Flag to indicate if requests coming from http://localhost
     * or http://127.0.0.1 should not be authenticated using
     * Kerberos.</p>
     * <p/>
     * <p>This feature helps to obviate the requirement of
     * creating an SPN for developer machines.</p>
     */
    public static final String ALLOW_LOCALHOST = "spnego.allow.localhost";

    /**
     * Servlet init param name in web.xml <b>spnego.allow.unsecure.basic</b>.
     * <p/>
     * <p>Set this value to <code>false</code> in web.xml if the filter
     * should reject connections that do not use SSL/TLS.</p>
     */
    public static final String ALLOW_UNSEC_BASIC = "spnego.allow.unsecure.basic";

    /**
     * HTTP Response Header <b>WWW-Authenticate</b>.
     * <p/>
     * <p>The filter will respond with this header with a value of "Basic"
     * and/or "Negotiate" (based on web.xml file).</p>
     */
    public static final String AUTHN_HEADER = "WWW-Authenticate";

    /**
     * HTTP Request Header <b>Authorization</b>.
     * <p/>
     * <p>Clients should send this header where the value is the
     * authentication token(s).</p>
     */
    public static final String AUTHZ_HEADER = "Authorization";

    /**
     * HTTP Response Header <b>Basic</b>.
     * <p/>
     * <p>The filter will set this as the value for the "WWW-Authenticate"
     * header if "Basic" auth is allowed (based on web.xml file).</p>
     */
    public static final String BASIC_HEADER = "Basic";

    /**
     * Servlet init param name in web.xml <b>spnego.login.client.module</b>.
     * <p/>
     * <p>The LoginModule name that exists in the login.conf file.</p>
     */
    public static final String CLIENT_MODULE = "spnego.login.client.module";

    /**
     * Servlet init param name in web.xml <b>spnego.krb5.conf</b>.
     * <p/>
     * <p>The location of the krb5.conf file. On Windows, this file will
     * sometimes be named krb5.ini and reside <code>%WINDOWS_ROOT%/krb5.ini</code>
     * here.</p>
     * <p/>
     * <p>By default, Java looks for the file in these locations and order:
     * <li>System Property (java.security.krb5.conf)</li>
     * <li>%JAVA_HOME%/lib/security/krb5.conf</li>
     * <li>%WINDOWS_ROOT%/krb5.ini</li>
     * </p>
     */
    public static final String KRB5_CONF = "spnego.krb5.conf";

    /**
     * Servlet init param name in web.xml <b>spnego.login.conf</b>.
     * <p/>
     * <p>The location of the login.conf file.</p>
     */
    public static final String LOGIN_CONF = "spnego.login.conf";

    /**
     * HTTP Response Header <b>Negotiate</b>.
     * <p/>
     * <p>The filter will set this as the value for the "WWW-Authenticate"
     * header. Note that the filter may also add another header with
     * a value of "Basic" (if allowed by the web.xml file).</p>
     */
    public static final String NEGOTIATE_HEADER = "Negotiate";

    /**
     * NTLM base64-encoded token start value.
     */
    static final String NTLM_PROLOG = "TlRMTVNT";

    /**
     * Servlet init param name in web.xml <b>spnego.preauth.password</b>.
     * <p/>
     * <p>Network Domain password. For Windows, this is sometimes known
     * as the Windows NT password.</p>
     */
    public static final String PREAUTH_PASSWORD = "spnego.preauth.password";

    /**
     * Servlet init param name in web.xml <b>spnego.preauth.username</b>.
     * <p/>
     * <p>Network Domain username. For Windows, this is sometimes known
     * as the Windows NT username.</p>
     */
    public static final String PREAUTH_USERNAME = "spnego.preauth.username";

    /**
     * If server receives an NTLM token, the filter will return with a 401
     * and with Basic as the only option (no Negotiate) <b>spnego.prompt.ntlm</b>.
     */
    public static final String PROMPT_NTLM = "spnego.prompt.ntlm";

    /**
     * Servlet init param name in web.xml <b>spnego.login.server.module</b>.
     * <p/>
     * <p>The LoginModule name that exists in the login.conf file.</p>
     */
    public static final String SERVER_MODULE = "spnego.login.server.module";
  }
}
