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

import javax.servlet.ServletRequest;

/**
 * The default installation of Internet Explorer and Active Directory
 * allow the user's/requester's credential to be delegated.
 * <p/>
 * <p>
 * By default, {@link SpnegoHttpURLConnection} has delegation set
 * to false. To allow delegation, call the <code>requestCredDeleg</code>
 * method on the <code>SpnegoHttpURLConnection</code> instance.
 * </p>
 * <p/>
 * <p>
 * Also, the server/service's pre-authentication account must be specified as
 * "Account is trusted for delegation" in Active Directory.
 * </p>
 * <p/>
 * <p>
 * Finally, the server/service's spnego servlet init params must be specified
 * to allow credential delegation by setting the property
 * <code>spnego.allow.delegation</code> to true (false by default).
 * </p>
 * <p/>
 * <p>
 * Custom client programs may request their credential to be delegated
 * by calling the <code>requestCredDeleg</code> on their instance of GSSContext.
 * </p>
 * <p/>
 * <p>
 * Java Application Servers can obtain the delegated credential by casting
 * the HTTP request.
 * </p>
 * <p/>
 * <p>
 * <b>Example usage:</b>
 * <pre>
 *     if (request instanceof DelegateServletRequest) {
 *         DelegateServletRequest dsr = (DelegateServletRequest) request;
 *         GSSCredential creds = dsr.getDelegatedCredential();
 *         ...
 *     }
 * </pre>
 * </p>
 * <p/>
 * <p>
 * To see a working example and instructions, take a look at the
 * <a href="http://spnego.sourceforge.net/credential_delegation.html"
 * target="_blank">credential delegation example</a>.
 * </p>
 * @author Darwin V. Felix
 */
public interface DelegateServletRequest extends ServletRequest {

  /**
   * Returns the requester's delegated credential.
   * <p/>
   * <p>
   * Returns null if request has no delegated credential
   * or if delegated credentials are not supported.
   * </p>
   * @return delegated credential or null
   */
  GSSCredential getDelegatedCredential();
}
