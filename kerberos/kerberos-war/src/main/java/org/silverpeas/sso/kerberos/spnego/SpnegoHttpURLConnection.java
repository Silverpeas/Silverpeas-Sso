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

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.silverpeas.sso.kerberos.spnego.KerberosSpnegoFilter.Constants;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static org.silverpeas.sso.kerberos.KerberosLogger.logger;

/**
 * This Class may be used by custom clients as a convenience when connecting
 * to a protected HTTP server.
 * <p/>
 * <p>
 * This mechanism is an alternative to HTTP Basic Authentication where the
 * HTTP server does not support Basic Auth but instead has SPNEGO support
 * (take a look at {@link KerberosSpnegoFilter}).
 * </p>
 * <p/>
 * <p>
 * A krb5.conf and a login.conf is required when using this class. Take a
 * look at the <a href="http://spnego.sourceforge.net" target="_blank">spnego.sourceforge.net</a>
 * documentation for an example krb5.conf and login.conf file.
 * Also, you must provide a keytab file, or a username and password, or allowtgtsessionkey.
 * </p>
 * <p/>
 * <p>
 * Example usage (username/password):
 * <pre>
 *     public static void main(final String[] args) throws Exception {
 *         System.setProperty("java.security.krb5.conf", "krb5.conf");
 *         System.setProperty("sun.security.krb5.debug", "true");
 *         System.setProperty("java.security.auth.login.config", "login.conf");
 *
 *         SpnegoHttpURLConnection spnego = null;
 *
 *         try {
 *             spnego = new SpnegoHttpURLConnection("spnego-client", "dfelix", "myp@s5");
 *             spnego.connect(new URL("http://medusa:8080/index.jsp"));
 *
 *             System.out.println(spnego.getResponseCode());
 *
 *         } finally {
 *             if (null != spnego) {
 *                 spnego.disconnect();
 *             }
 *         }
 *     }
 * </pre>
 * </p>
 * <p/>
 * <p>
 * Alternatively, if the server supports HTTP Basic Authentication, this Class
 * is NOT needed and instead you can do something like the following:
 * <pre>
 *     public static void main(final String[] args) throws Exception {
 *         final String creds = "dfelix:myp@s5";
 *
 *         final String token = Base64.encode(creds.getBytes());
 *
 *         URL url = new URL("http://medusa:8080/index.jsp");
 *
 *         HttpURLConnection conn = (HttpURLConnection) url.openConnection();
 *
 *         conn.setRequestProperty(Constants.AUTHZ_HEADER
 *                 , Constants.BASIC_HEADER + " " + token);
 *
 *         conn.connect();
 *
 *         System.out.println("Response Code:" + conn.getResponseCode());
 *     }
 * </pre>
 * </p>
 * <p/>
 * <p>
 * To see a working example and instructions on how to use a keytab, take
 * a look at the <a href="http://spnego.sourceforge.net/client_keytab.html"
 * target="_blank">creating a client keytab</a> example.
 * </p>
 * <p/>
 * <p/>
 * Finally, the {@link SpnegoSOAPConnection} class is another example of a class
 * that uses this class.
 * <p/>
 * @author Darwin V. Felix
 */
public final class SpnegoHttpURLConnection {

  /**
   * GSSContext is not thread-safe.
   */
  private static final Lock LOCK = new ReentrantLock();

  private static final byte[] EMPTY_BYTE = new byte[0];

  /**
   * If false, this connection object has not created a communications link to
   * the specified URL. If true, the communications link has been established.
   */
  private boolean connected = false;

  /**
   * Default is GET.
   * @see HttpURLConnection#getRequestMethod()
   */
  private String requestMethod = "GET";

  /**
   * @see java.net.URLConnection#getRequestProperties()
   */
  private final Map<String, List<String>> requestProperties = new LinkedHashMap<>();

  /**
   * Login Context for authenticating client. If username/password
   * or GSSCredential is provided (in constructor) then this
   * field will always be null.
   */
  private final LoginContext loginContext;

  /**
   * Client's credentials. If username/password or LoginContext is provided
   * (in constructor) then this field will always be null.
   */
  private GSSCredential credential;

  /**
   * Flag to determine if GSSContext has been established. Users of this
   * class should always check that this field is true before using/trusting
   * the contents of the response.
   */
  private boolean cntxtEstablished = false;

  /**
   * Ref to HTTP URL Connection object after calling connect method.
   * Always call spnego.disconnect() when done using this class.
   */
  private HttpURLConnection conn = null;

  /**
   * Request credential to be delegated.
   * Default is false.
   */
  private boolean reqCredDeleg = false;

  /**
   * Determines if the GSSCredentials (if any) used during the
   * connection request should be automatically disposed by
   * this class when finished.
   * Default is true.
   */
  private boolean autoDisposeCreds = true;

  /**
   * Creates an instance where the LoginContext relies on a keytab
   * file being specified by "java.security.auth.login.config" or
   * where LoginContext relies on tgtsessionkey.
   * @param loginModuleName name of the login module
   * @throws LoginException if the authentication fails
   */
  public SpnegoHttpURLConnection(final String loginModuleName) throws LoginException {

    this.loginContext = new LoginContext(loginModuleName);
    this.loginContext.login();
    this.credential = null;
  }

  /**
   * Create an instance where the GSSCredential is specified by the parameter
   * and where the GSSCredential is automatically disposed after use.
   * @param creds credentials to use
   */
  @SuppressWarnings("unused")
  public SpnegoHttpURLConnection(final GSSCredential creds) {
    this(creds, true);
  }

  /**
   * Create an instance where the GSSCredential is specified by the parameter
   * and whether the GSSCredential should be disposed after use.
   * @param creds credentials to use
   * @param dispose true if GSSCredential should be diposed after use
   */
  public SpnegoHttpURLConnection(final GSSCredential creds, final boolean dispose) {
    this.loginContext = null;
    this.credential = creds;
    this.autoDisposeCreds = dispose;
  }

  /**
   * Creates an instance where the LoginContext does not require a keytab
   * file. However, the "java.security.auth.login.config" property must still
   * be set prior to instantiating this object.
   * @param loginModuleName the name of the login module
   * @param username the login id of the user
   * @param password the password of the user
   * @throws LoginException if the authentication fails.
   */
  public SpnegoHttpURLConnection(final String loginModuleName, final String username,
      final String password) throws LoginException {

    final CallbackHandler handler = SpnegoProvider.getUsernamePasswordHandler(username, password);

    this.loginContext = new LoginContext(loginModuleName, handler);
    this.loginContext.login();
    this.credential = null;
  }

  /**
   * Throws IllegalStateException if this connection object has not yet created
   * a communications link to the specified URL.
   */
  private void assertConnected() {
    if (!this.connected) {
      throw new IllegalStateException("Not connected.");
    }
  }

  /**
   * Throws IllegalStateException if this connection object has already created
   * a communications link to the specified URL.
   */
  private void assertNotConnected() {
    if (this.connected) {
      throw new IllegalStateException("Already connected.");
    }
  }

  @SuppressWarnings("UnusedReturnValue")
  public HttpURLConnection connect(final URL url, final ByteArrayOutputStream dooutput)
      throws GSSException, PrivilegedActionException, IOException {
    return this.connect(url, null, dooutput);
  }

  /**
   * Opens a communications link to the resource referenced by
   * this URL, if such a connection has not already been established.
   * @param url the URL of the resource
   * @param proxy a possible proxy to use to establish a connection with the resource
   * @param output optional message/payload to send to server
   * @return an HttpURLConnection object
   * @throws GSSException if the SSO negotiation fails
   * @throws PrivilegedActionException if a disallowed action is performed.
   * @throws IOException if an IO occurs during the connection
   * @see java.net.URLConnection#connect()
   */
  public HttpURLConnection connect(final URL url, final Proxy proxy,
      final ByteArrayOutputStream output)
      throws GSSException, PrivilegedActionException, IOException {

    assertNotConnected();

    GSSContext context = null;

    try {
      byte[] data;

      SpnegoHttpURLConnection.LOCK.lock();
      try {
        // work-around to GSSContext/AD timestamp vs sequence field replay bug
        waitSomeTimes();

        context = this.getGSSContext(url);
        context.requestMutualAuth(true);
        context.requestConf(true);
        context.requestInteg(true);
        context.requestReplayDet(true);
        context.requestSequenceDet(true);
        context.requestCredDeleg(this.reqCredDeleg);

        data = context.initSecContext(EMPTY_BYTE, 0, 0);
      } finally {
        SpnegoHttpURLConnection.LOCK.unlock();
      }

      if (proxy == null) {
        this.conn = (HttpURLConnection) url.openConnection();
      } else {
        this.conn = (HttpURLConnection) url.openConnection(proxy);
      }
      this.connected = true;

      final Set<String> keys = this.requestProperties.keySet();
      for (final String key : keys) {
        for (String value : this.requestProperties.get(key)) {
          this.conn.addRequestProperty(key, value);
        }
      }

      // TODO : re-factor to support (302) redirects
      this.conn.setInstanceFollowRedirects(false);
      this.conn.setRequestMethod(this.requestMethod);

      this.conn.setRequestProperty(Constants.AUTHZ_HEADER,
          Constants.NEGOTIATE_HEADER + ' ' + Base64.encode(data));

      if (null != output && output.size() > 0) {
        this.conn.setDoOutput(true);
        output.writeTo(this.conn.getOutputStream());
      }

      this.conn.connect();

      final SpnegoAuthScheme scheme =
          SpnegoProvider.getAuthScheme(this.conn.getHeaderField(Constants.AUTHN_HEADER));

      // app servers will not return a WWW-Authenticate on 302, (and 30x...?)
      if (null == scheme) {
        logger().debug("SpnegoProvider.getAuthScheme(...) returned null.");

      } else {
        data = scheme.getToken();

        if (Constants.NEGOTIATE_HEADER.equalsIgnoreCase(scheme.getScheme())) {
          SpnegoHttpURLConnection.LOCK.lock();
          try {
            data = context.initSecContext(data, 0, data.length);
          } finally {
            SpnegoHttpURLConnection.LOCK.unlock();
          }

          // TODO : support context loops where i>1
          if (null != data) {
            logger().warn("Server requested context loop: " + data.length);
          }

        } else {
          throw new UnsupportedOperationException("Scheme NOT Supported: " + scheme.getScheme());
        }

        this.cntxtEstablished = context.isEstablished();
      }
    } finally {
      this.dispose(context);
    }

    return this.conn;
  }

  private static void waitSomeTimes() {
    try {
      Thread.sleep(31);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  /**
   * Logout the LoginContext instance, and call dispose() on GSSCredential
   * if autoDisposeCreds is set to true, and call dispose on the passed-in
   * GSSContext instance.
   */
  private void dispose(final GSSContext context) {
    if (null != context) {
      try {
        SpnegoHttpURLConnection.LOCK.lock();
        try {
          context.dispose();
        } finally {
          SpnegoHttpURLConnection.LOCK.unlock();
        }
      } catch (GSSException gsse) {
        logger().warn("call to dispose context failed. {0}", gsse.getMessage());
      }
    }

    if (null != this.credential && this.autoDisposeCreds) {
      try {
        this.credential.dispose();
      } catch (final GSSException gsse) {
        logger().warn("call to dispose credential failed. {0}", gsse.getMessage());
      }
    }

    if (null != this.loginContext) {
      try {
        this.loginContext.logout();
      } catch (final LoginException le) {
        logger().warn("call to logout context failed. {0}", le.getMessage());
      }
    }
  }

  /**
   * Logout and clear request properties.
   * @see HttpURLConnection#disconnect()
   */
  public void disconnect() {
    this.dispose(null);
    this.requestProperties.clear();
    this.connected = false;
    if (null != this.conn) {
      this.conn.disconnect();
    }
  }

  /**
   * Returns true if GSSContext has been established.
   * @return true if GSSContext has been established, false otherwise.
   */
  @SuppressWarnings("unused")
  public boolean isContextEstablished() {
    return this.cntxtEstablished;
  }

  /**
   * Internal sanity check to validate not null key/value pairs.
   */
  private void assertKeyValue(final String key, final String value) {
    if (null == key || key.isEmpty()) {
      throw new IllegalArgumentException("key parameter is null or empty");
    }
    if (null == value) {
      throw new IllegalArgumentException("value parameter is null");
    }
  }

  /**
   * Adds an HTTP Request property.
   * @param key request property name
   * @param value request propery value
   * @see java.net.URLConnection#addRequestProperty(String, String)
   */
  public void addRequestProperty(final String key, final String value) {
    assertNotConnected();
    assertKeyValue(key, value);

    if (this.requestProperties.containsKey(key)) {
      final List<String> val = this.requestProperties.get(key);
      val.add(value);
      this.requestProperties.put(key, val);
    } else {
      setRequestProperty(key, value);
    }
  }

  /**
   * Sets an HTTP Request property.
   * @param key request property name
   * @param value request property value
   * @see java.net.URLConnection#setRequestProperty(String, String)
   */
  public void setRequestProperty(final String key, final String value) {
    assertNotConnected();
    assertKeyValue(key, value);

    this.requestProperties.put(key, Collections.singletonList(value));
  }

  /**
   * Returns a GSSContextt for the given url with a default lifetime.
   * @param url http address
   * @return GSSContext for the given url
   * @throws GSSException if the SSO negotiation fails.
   * @throws PrivilegedActionException if a disallowed action is performed.
   */
  private GSSContext getGSSContext(final URL url) throws GSSException, PrivilegedActionException {

    if (null == this.credential) {
      if (null == this.loginContext) {
        throw new IllegalStateException("GSSCredential AND LoginContext NOT initialized");

      } else {
        this.credential = SpnegoProvider.getClientCredential(this.loginContext.getSubject());
      }
    }

    return SpnegoProvider.getGSSContext(this.credential, url);
  }

  /**
   * Returns an error stream that reads from this open connection.
   * @return error stream that reads from this open connection
   * @see HttpURLConnection#getErrorStream()
   */
  public InputStream getErrorStream() {
    assertConnected();

    return this.conn.getErrorStream();
  }

  /**
   * Returns an input stream that reads from this open connection.
   * @return input stream that reads from this open connection
   * @throws IOException if an IO error occurs
   * @see HttpURLConnection#getInputStream()
   */
  public InputStream getInputStream() throws IOException {
    assertConnected();

    return this.conn.getInputStream();
  }

  /**
   * Request that this GSSCredential be allowed for delegation.
   * @param requestDelegation true to allow/request delegation
   */
  @SuppressWarnings("unused")
  public void requestCredDeleg(final boolean requestDelegation) {
    this.assertNotConnected();

    this.reqCredDeleg = requestDelegation;
  }

  /**
   * May override the default GET method.
   * @param method the HTTP method to use
   * @see HttpURLConnection#setRequestMethod(String)
   */
  @SuppressWarnings("unused")
  public void setRequestMethod(final String method) {
    assertNotConnected();

    this.requestMethod = method;
  }
}
