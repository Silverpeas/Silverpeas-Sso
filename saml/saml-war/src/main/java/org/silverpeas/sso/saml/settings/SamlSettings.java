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

package org.silverpeas.sso.saml.settings;

import org.apache.commons.lang3.tuple.Pair;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.silverpeas.core.SilverpeasRuntimeException;
import org.silverpeas.core.admin.domain.DomainType;
import org.silverpeas.core.util.ResourceLocator;
import org.silverpeas.core.util.SettingBundle;

import javax.servlet.http.HttpServletRequest;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static java.text.MessageFormat.format;
import static org.silverpeas.core.util.StringUtil.*;
import static org.silverpeas.sso.saml.SamlLogger.logger;

/**
 * @author silveryocha
 */
public class SamlSettings {
  private static final String APPLICATION_URL = ResourceLocator.getGeneralSettingBundle()
      .getString("ApplicationURL", "/silverpeas");
  private static final int DEFAULT_HTTP_PORT = 80;
  private static final int DEFAULT_HTTPS_PORT = 443;
  private static final String SETTINGS_PATH = "org.silverpeas.sso.saml";
  private static Map<String, Pair<String, BasicX509Credential>> idpCertificateCache = new
      HashMap<>();

  private SamlSettings() {
  }

  private static SettingBundle getSettings() {
    return ResourceLocator.getSettingBundle(SETTINGS_PATH);
  }

  private static String getServerUrl(final HttpServletRequest request) {
    String absoluteUrl = "";
    if (request != null) {
      absoluteUrl = request.getScheme() + "://" + request.getServerName();
      if (request.getServerPort() != DEFAULT_HTTP_PORT &&
          request.getServerPort() != DEFAULT_HTTPS_PORT) {
        absoluteUrl += ":" + request.getServerPort();
      }
    }
    return ResourceLocator.getGeneralSettingBundle().getString("httpServerBase", absoluteUrl);
  }

  /**
   * Gets the silverpeas's domain types the SSO is linked to.
   * @return a Stream of {@link DomainType}.
   */
  public static Stream<DomainType> getSilverpeasDomainTypes() {
    return Stream.of(getSettings().getString("silverpeas.domain.type").split("[,; ]"))
        .map(String::trim).filter(d -> !d.isEmpty()).map(DomainType::valueOf);
  }

  /**
   * Gets the silverpeas domain identifier.
   * @return a string.
   */
  private static String getSilverpeasDefaultDomainId() {
    return getSettings().getString("saml.silverpeas.default.domain.id");
  }

  /**
   * Gets the domain id identifier from given request, or from default settings if none.
   * @return a string.
   */
  public static String getSilverpeasDomainId(final HttpServletRequest httpRequest) {
    final String domainId = defaultStringIfNotDefined(httpRequest.getParameter("domainId"),
        getSilverpeasDefaultDomainId());
    if (isNotDefined(domainId)) {
      throw new SilverpeasRuntimeException("no domain identifier specified");
    }
    return domainId;
  }

  /**
   * Gets the SSO SAML URL.
   * @return a string.
   */
  public static String getSsoServiceUrl(final HttpServletRequest httpRequest) {
    return getSettings()
        .getString(format("domain.{0}.saml.sso.service.url", getSilverpeasDomainId(httpRequest)));
  }

  /**
   * Gets the Assertion Consumer Service URL.
   * @return a string.
   */
  public static String getAssertionConsumerServiceUrl(final HttpServletRequest httpRequest) {
    String url = getServerUrl(httpRequest) + APPLICATION_URL + "/sso/saml";
    final String domainId = httpRequest.getParameter("domainId");
    if (isDefined(domainId) && !domainId.equals(getSilverpeasDefaultDomainId())) {
      url += "?domainId=" + domainId;
    }
    return url;
  }

  /**
   * Gets the Artifact Resolution Service URL.
   * @return a string.
   */
  public static String getArtifactResolutionServiceUrl(final HttpServletRequest httpRequest) {
    return getSettings().getString(format("domain.{0}.saml.artifact.resolution.service.url",
        getSilverpeasDomainId(httpRequest)));
  }

  /**
   * Gets the entity identifier.
   * @return a string.
   */
  public static String getEntityId(final HttpServletRequest httpRequest) {
    return getServerUrl(httpRequest) + APPLICATION_URL;
  }

  /**
   * Gets the IDP certificate key.
   * @return a string.
   */
  public static synchronized Credential getIdpCredential(
      final HttpServletRequest httpRequest) {
    final String domainId = getSilverpeasDomainId(httpRequest);
    Pair<String, BasicX509Credential> idpCertificateDomainCache = idpCertificateCache
        .computeIfAbsent(domainId, k -> Pair.of("", null));
    final String idpCertificateDomainPathAsString = getSettings()
        .getString(format("domain.{0}.saml.idp.public.certificate.path", domainId));
    if (!idpCertificateDomainPathAsString.equals(idpCertificateDomainCache.getKey())) {
      final Path certificateDomainPath = Paths.get(idpCertificateDomainPathAsString);
      try (final InputStream in = Files.newInputStream(certificateDomainPath)) {
        final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        final X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
        final BasicX509Credential idpCredential = CredentialSupport.getSimpleCredential(cert, null);
        idpCredential.setUsageType(UsageType.SIGNING);
        idpCertificateDomainCache = Pair.of(idpCertificateDomainPathAsString, idpCredential);
      } catch (Exception e) {
        logger().error(e);
        idpCertificateDomainCache = Pair.of("", null);
      }
      idpCertificateCache.put(domainId, idpCertificateDomainCache);
    }
    return idpCertificateDomainCache.getValue();
  }
}
