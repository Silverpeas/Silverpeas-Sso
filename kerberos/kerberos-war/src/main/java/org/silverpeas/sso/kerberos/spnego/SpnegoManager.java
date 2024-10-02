/*
 * Copyright (C) 2000 - 2023 Silverpeas
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package org.silverpeas.sso.kerberos.spnego;

import org.ietf.jgss.GSSException;
import org.silverpeas.core.annotation.Service;
import org.silverpeas.core.util.ServiceProvider;

import javax.inject.Singleton;
import javax.security.auth.login.LoginException;
import java.security.PrivilegedActionException;

import static java.util.Optional.ofNullable;
import static org.silverpeas.sso.kerberos.KerberosLogger.logger;

/**
 * This provider allows to keep configuration elements in memory in order to perform some
 * configuration reloading without having to reboot the Silverpeas's server.
 * @author silveryocha
 */
@Service
@Singleton
public class SpnegoManager {

  /**
   * Object for performing Basic and SPNEGO authentication.
   */
  private SpnegoFilterConfig config = null;
  private SpnegoAuthenticator authenticator = null;

  public static SpnegoManager get() {
    return ServiceProvider.getService(SpnegoManager.class);
  }

  /**
   * Initializing the manager with spnego configuration.
   * @param config a {@link SpnegoFilterConfig} instance.
   */
  void init(final SpnegoFilterConfig config) {
    this.config = config;
    initializeAuthenticator();
  }

  void initializeAuthenticator() {
    synchronized (SpnegoFilterConfig.class) {
      if (null == this.authenticator) {
        try {
          this.authenticator = new SpnegoAuthenticator(config);
        } catch (final LoginException | GSSException | PrivilegedActionException e) {
          logger().error(e);
          throw new SpnegoUnauthenticatedException(e.getMessage());
        }
      }
    }
  }

  /**
   * Gets the authenticator instance.
   * @return the {@link SpnegoAuthenticator} instance.
   * @throws SpnegoUnauthenticatedException when no authenticator exists.
   */
  SpnegoAuthenticator getAuthenticator() {
    return ofNullable(this.authenticator)
        .orElseThrow(() -> new SpnegoUnauthenticatedException("Authenticator does not exist"));
  }


  /**
   * Returns true if typed runtime exceptions have to be thrown.
   * @return true if typed runtime exceptions have to be thrown
   */
  boolean isTypedRuntimeExceptionThrown() {
    return config.isTypedRuntimeExceptionThrown();
  }

  /**
   * Logout. Since server uses LoginContext to login/pre-authenticate, we must
   * also logout when we are done using this object.
   * <p/>
   * <p>
   * Generally, instantiations of this class should be the only to call
   * dispose() as it indicates that this class will no longer be used.
   * </p>
   */
  void logoutAuthenticator() {
    if (this.authenticator != null) {
      this.authenticator.dispose();
      this.authenticator = null;
    }
  }

  /**
   * Performs a reload of the Spnego configuration.
   */
  public void reload() {
    logoutAuthenticator();
    initializeAuthenticator();
  }
}
