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

package org.silverpeas.sso.kerberos.spnego;

import org.ietf.jgss.GSSCredential;

import javax.security.auth.kerberos.KerberosPrincipal;
import java.security.Principal;

/**
 * This class encapsulates a KerberosPrincipal.
 * <p/>
 * <p>This class also has a reference to the client's/requester's
 * delegated credential (if any). See the {@link DelegateServletRequest}
 * documentation for more details.</p>
 * <p/>
 * <p>Also, see the delegation examples at
 * <a href="http://spnego.sourceforge.net" target="_blank">http://spnego.sourceforge.net</a>
 * </p>
 * @author Darwin V. Felix
 */
public final class SpnegoPrincipal implements Principal {

  private final transient KerberosPrincipal kerberosPrincipal;

  private final transient GSSCredential delegatedCred;

  /**
   * Constructs a SpnegoPrincipal from the provided String input.
   * @param name the principal name
   */
  public SpnegoPrincipal(final String name) {
    this.kerberosPrincipal = new KerberosPrincipal(name);
    this.delegatedCred = null;
  }

  /**
   * Constructs a SpnegoPrincipal from the provided String input
   * and name type input.
   * @param name the principal name
   * @param nameType the name type of the principal
   */
  public SpnegoPrincipal(final String name, final int nameType) {
    this.kerberosPrincipal = new KerberosPrincipal(name, nameType);
    this.delegatedCred = null;
  }

  /**
   * Constructs a SpnegoPrincipal from the provided String input
   * and name type input.
   * @param name the principal name
   * @param nameType the name type of the principal
   * @param delegCred this principal's delegated credential (if any)
   */
  public SpnegoPrincipal(final String name, final int nameType, final GSSCredential delegCred) {

    this.kerberosPrincipal = new KerberosPrincipal(name, nameType);
    this.delegatedCred = delegCred;
  }

  /**
   * Returns this Principal's delegated credential or null.
   * @return Principal's delegated credential or null.
   */
  public GSSCredential getDelegatedCredential() {
    return this.delegatedCred;
  }

  @Override
  public String getName() {
    return this.kerberosPrincipal.getName();
  }

  /**
   * Returns the name type of the KerberosPrincipal.
   * @return name type of the KerberosPrincipal
   */
  public int getNameType() {
    return this.kerberosPrincipal.getNameType();
  }

  /**
   * Returns the realm component of this Kerberos principal.
   * @return realm component of this Kerberos principal
   */
  public String getRealm() {
    return this.kerberosPrincipal.getRealm();
  }

  @Override
  public int hashCode() {
    return this.kerberosPrincipal.hashCode();
  }

  @Override
  public String toString() {
    return this.kerberosPrincipal.toString();
  }
}
