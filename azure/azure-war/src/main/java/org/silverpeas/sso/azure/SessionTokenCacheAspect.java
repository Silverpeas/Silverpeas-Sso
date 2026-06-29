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

import com.microsoft.aad.msal4j.ITokenCacheAccessAspect;
import com.microsoft.aad.msal4j.ITokenCacheAccessContext;
import org.silverpeas.kernel.util.StringUtil;

/**
 * MSAL4J manages its tokens (including the refresh token used for silent renewal) into an internal
 * token cache attached to the {@link com.microsoft.aad.msal4j.ConfidentialClientApplication}
 * instance. As a new client application is built on each request, this aspect is used to round-trip
 * that cache through a serialized form stored in the HTTP session: the cache is restored before any
 * access and the (possibly updated) serialized form is read back after access.
 *
 * @author mmoquillon
 */
class SessionTokenCacheAspect implements ITokenCacheAccessAspect {

  private String serializedCache;

  SessionTokenCacheAspect(final String serializedCache) {
    this.serializedCache = serializedCache;
  }

  @Override
  public void beforeCacheAccess(final ITokenCacheAccessContext context) {
    if (StringUtil.isDefined(serializedCache)) {
      context.tokenCache().deserialize(serializedCache);
    }
  }

  @Override
  public void afterCacheAccess(final ITokenCacheAccessContext context) {
    serializedCache = context.tokenCache().serialize();
  }

  String getSerializedCache() {
    return serializedCache;
  }
}
