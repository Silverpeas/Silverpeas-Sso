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

package org.silverpeas.sso.azure.settings;

import org.silverpeas.core.util.ResourceLocator;
import org.silverpeas.core.util.SettingBundle;

import javax.ws.rs.core.UriBuilder;

/**
 * @author silveryocha
 */
public class AzureSettings {
  private static final String SETTINGS_PATH = "org.silverpeas.sso.azure";

  private AzureSettings() {
  }

  private static SettingBundle getSettings() {
    return ResourceLocator.getSettingBundle(SETTINGS_PATH);
  }

  /**
   * Gets the authority URI
   * @return uri as string.
   */
  private static String getAuthorityUri() {
    return getSettings().getString("azure.authority.uri");
  }

  /**
   * Gets the tenant name.
   * @return a string.
   */
  private static String getTenantName() {
    return getSettings().getString("azure.silverpeas.client.tenant.name");
  }

  /**
   * Gets the tenant authority URI
   * @return uri as string.
   */
  public static String getTenantAuthorityPath() {
    return UriBuilder.fromPath(getAuthorityUri()).path(getTenantName()).build().toString() +  "/";
  }

  /**
   * Gets the client identifier.
   * @return identifier as string.
   */
  public static String getClientId() {
    return getSettings().getString("azure.silverpeas.client.id");
  }

  /**
   * Gets the client secret key.
   * @return key as base64 string.
   */
  public static String getClientSecretKey() {
    return getSettings().getString("azure.silverpeas.client.secret");
  }

  /**
   * Gets the silverpeas domain identifier.
   * @return a string.
   */
  public static String getSilverpeasDomainId() {
    return getSettings().getString("azure.silverpeas.domain.id");
  }
}
