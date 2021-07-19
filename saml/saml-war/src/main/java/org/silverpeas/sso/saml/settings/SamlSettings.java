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

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.SAMLRuntimeException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SSODescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.silverpeas.core.SilverpeasRuntimeException;
import org.silverpeas.core.admin.domain.DomainType;
import org.silverpeas.core.util.Pair;
import org.silverpeas.core.util.ResourceLocator;
import org.silverpeas.core.util.SettingBundle;
import org.silverpeas.core.util.StringUtil;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static java.text.MessageFormat.format;
import static java.util.Objects.nonNull;
import static java.util.Optional.of;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toMap;
import static org.opensaml.saml.saml2.core.AuthnContext.*;
import static org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration.*;
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
  private static final Predicate<Pair<String, Credential>> VALID_CREDENTIAL = p -> nonNull(p.getSecond());
  private static final Map<String, Pair<String, XmlMetadataDataProvider>> METADATA_CACHE = new HashMap<>();
  private static final Map<String, Pair<String, Credential>> CREDENTIAL_CACHE = new HashMap<>();
  private static final Map<String, AuthnContextComparisonTypeEnumeration> AC_COMPARISONS = Stream
      .of(EXACT, MINIMUM, MAXIMUM, BETTER)
      .collect(toMap(c -> c.toString().toLowerCase(), c -> c));
  private static final Map<String, String> AC_CLASSES = Stream
      .of(IP_AUTHN_CTX, IP_PASSWORD_AUTHN_CTX, KERBEROS_AUTHN_CTX, MOFU_AUTHN_CTX, MTFU_AUTHN_CTX,
          MOFC_AUTHN_CTX, MTFC_AUTHN_CTX, PASSWORD_AUTHN_CTX, PPT_AUTHN_CTX,
          PREVIOUS_SESSION_AUTHN_CTX, X509_AUTHN_CTX, PGP_AUTHN_CTX, SPKI_AUTHN_CTX,
          XML_DSIG_AUTHN_CTX, SMARTCARD_AUTHN_CTX, SMARTCARD_PKI_AUTHN_CTX, SOFTWARE_PKI_AUTHN_CTX,
          TELEPHONY_AUTHN_CTX, NOMAD_TELEPHONY_AUTHN_CTX, PERSONAL_TELEPHONY_AUTHN_CTX,
          AUTHENTICATED_TELEPHONY_AUTHN_CTX, SRP_AUTHN_CTX, TLS_CLIENT_AUTHN_CTX,
          TIME_SYNC_TOKEN_AUTHN_CTX, UNSPECIFIED_AUTHN_CTX)
      .collect(toMap(s -> {
        final String[] split = s.split("[:]");
        return split[split.length - 1].toLowerCase();
      }, c -> c));

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
   * Gets the silverpeas domain identifier.
   * @return a string.
   */
  private static String getSilverpeasDefaultDomainId() {
    return getSettings().getString("saml.silverpeas.default.domain.id");
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
    return getIdpSsoDescriptor(httpRequest)
        .stream()
        .flatMap(d -> d.getSingleSignOnServices().stream())
        .filter(d -> d.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI))
        .map(Endpoint::getLocation)
        .filter(StringUtil::isDefined)
        .findFirst()
        .orElseGet(() -> getSettings()
            .getString(format("domain.{0}.saml.sso.service.url", getSilverpeasDomainId(httpRequest))));
  }

  /**
   * Gets the Assertion Consumer Service URL.
   * @return a string.
   */
  public static String getAssertionConsumerServiceUrl(final HttpServletRequest httpRequest) {
    String url = getServerUrl(httpRequest) + APPLICATION_URL + "/sso/saml";
    final String domainId = httpRequest.getParameter("domainId");
    if (isDefined(domainId)) {
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
   * Indicates if the 'notBefore' condition is enabled for assertion.
   * @return true if enabled, false otherwise.
   */
  public static boolean isNotBeforeAssertionConditionEnabled(final HttpServletRequest httpRequest) {
    return getSettings().getBoolean(format("domain.{0}.saml.assertion.condition.notBefore.enabled",
        getSilverpeasDomainId(httpRequest)), true);
  }

  /**
   * Indicates if the 'notOnOrAfter' condition is enabled for assertion.
   * @return true if enabled, false otherwise.
   */
  public static boolean isNotOnOrAfterAssertionConditionEnabled(final HttpServletRequest httpRequest) {
    return getSettings().getBoolean(format("domain.{0}.saml.assertion.condition.notOnOrAfter.enabled",
        getSilverpeasDomainId(httpRequest)), true);
  }

  /**
   * Gets the entity identifier.
   * @return a string.
   */
  public static String getEntityId(final HttpServletRequest httpRequest) {
    return getServerUrl(httpRequest) + APPLICATION_URL;
  }

  /**
   * Gets the SP credential.
   * @return a string.
   */
  public static Optional<Credential> getSpCredential(final HttpServletRequest httpRequest) {
    return getCredential(httpRequest, Actor.SP, getSpSsoDescriptor(httpRequest).orElse(null));
  }

  /**
   * Gets the IDP credential.
   * @return a string.
   */
  public static Credential getIdpCredential(final HttpServletRequest httpRequest) {
    return getCredential(httpRequest, Actor.IDP, getIdpSsoDescriptor(httpRequest).orElse(null))
        .orElseThrow(() -> new SilverpeasRuntimeException("No IDP credential found"));
  }

  private static synchronized Optional<Credential> getCachedCredential(
      final HttpServletRequest httpRequest, final Actor actor) {
    final String actorAsString = actor.name().toLowerCase();
    final String domainId = getSilverpeasDomainId(httpRequest);
    final String cacheKey = actorAsString + ":" + domainId;
    return of(CREDENTIAL_CACHE.compute(cacheKey, (k, a) -> {
          final Pair<String, Credential> actual = a == null ? Pair.of("", null) : a;
          Pair<String, Credential> newOne = getCredentialFromX509CertificatePath(domainId, actorAsString, actual);
          if (!VALID_CREDENTIAL.test(newOne)) {
            newOne = getCredentialFromKeystorePath(domainId, actorAsString, actual);
          }
          return newOne;
        }))
        .filter(VALID_CREDENTIAL)
        .map(Pair::getSecond);
  }

  /**
   * Gets the SP credential.
   * @return a string.
   */
  private static Optional<Credential> getCredential(final HttpServletRequest httpRequest,
      final Actor actor, final SSODescriptor ssoDescriptor) {
    return ofNullable(ofNullable(ssoDescriptor)
        .stream()
        .flatMap(d -> d.getKeyDescriptors().stream())
        .filter(k -> UsageType.SIGNING.equals(k.getUse()))
        .flatMap(k -> k.getKeyInfo().getX509Datas().stream())
        .flatMap(x -> x.getX509Certificates().stream())
        .map(c -> {
          try {
            final X509Certificate certificate = KeyInfoSupport.getCertificate(c);
            if (certificate != null) {
              final BasicX509Credential credential = CredentialSupport.getSimpleCredential(certificate, null);
              credential.setUsageType(UsageType.SIGNING);
              return (Credential) credential;
            }
            return null;
          } catch (CertificateException e) {
            throw new SAMLRuntimeException(e);
          }
        })
        .findFirst()
        .orElseGet(() -> getCachedCredential(httpRequest, actor).orElse(null)));
  }

  private static Pair<String, Credential> getCredentialFromX509CertificatePath(
      final String domainId, final String actor, Pair<String, Credential> actual) {
    final Optional<String> certificatePath = ofNullable(getSettings().getString(
        format("domain.{0}.saml.{1}.public.certificate.path", domainId, actor), null));
    if (certificatePath.isPresent() && !certificatePath.get().equals(actual.getFirst())) {
      final Path certificateDomainPath = Paths.get(certificatePath.get());
      try (final InputStream in = Files.newInputStream(certificateDomainPath)) {
        final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        final X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
        final BasicX509Credential credential = CredentialSupport.getSimpleCredential(cert, null);
        ofNullable(getSettings().getString(
            format("domain.{0}.saml.{1}.private.key.path", domainId, actor), null)).ifPresent(k -> {
              final File privateKeyFile = new File(k);
          try {
            final PrivateKey privateKey = KeySupport.decodePrivateKey(privateKeyFile, ofNullable(
                getSettings().getString(format("domain.{0}.saml.{1}.private.key.pass", domainId, actor), null))
                .map(String::toCharArray)
                .orElse(null));
            credential.setPrivateKey(privateKey);
          } catch (KeyException e) {
            throw new SAMLRuntimeException(e);
          }
        });
        credential.setUsageType(UsageType.SIGNING);
        return Pair.of(certificatePath.get(), credential);
      } catch (Exception e) {
        logger().error(e);
        return Pair.of("", null);
      }
    }
    return actual;
  }

  private static Pair<String, Credential> getCredentialFromKeystorePath(
      final String domainId, final String actor, Pair<String, Credential> actual) {
    final KeystorePathData keystoreData = new KeystorePathData(domainId, actor);
    if (keystoreData.isValid() && !keystoreData.getPath().equals(actual.getFirst())) {
      final Path keystoreDomainPath = Paths.get(keystoreData.getPath());
      try (final InputStream in = Files.newInputStream(keystoreDomainPath)) {
        final KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(in, keystoreData.getPassword().toCharArray());
        final Map<String, String> passwordMap = new HashMap<>();
        passwordMap.put(keystoreData.getEntryId(), keystoreData.getEntryPassword());
        final KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);
        final Criterion criterion = new EntityIdCriterion(keystoreData.getEntryId());
        final CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(criterion);
        final Credential credential = resolver.resolveSingle(criteriaSet);
        return Pair.of(keystoreData.getPath(), credential);
      } catch (Exception e) {
        logger().error(e);
        return Pair.of("", null);
      }
    }
    return actual;
  }

  private static synchronized Optional<SPSSODescriptor> getSpSsoDescriptor(
      final HttpServletRequest httpRequest) {
    return getEntityDescriptor(httpRequest, Actor.SP)
        .map(d -> d.getSPSSODescriptor(SAMLConstants.SAML20P_NS));
  }

  private static synchronized Optional<IDPSSODescriptor> getIdpSsoDescriptor(
      final HttpServletRequest httpRequest) {
    return getEntityDescriptor(httpRequest, Actor.IDP)
        .map(d -> d.getIDPSSODescriptor(SAMLConstants.SAML20P_NS));
  }

  private static synchronized Optional<EntityDescriptor> getEntityDescriptor(
      final HttpServletRequest httpRequest, final Actor actor) {
    final String actorAsString = actor.name().toLowerCase();
    final String domainId = getSilverpeasDomainId(httpRequest);
    return ofNullable(getSettings().getString(format("domain.{0}.saml.{1}.xml.metadata.path", domainId, actorAsString), null))
        .map(
          p -> METADATA_CACHE.compute(domainId, (k, a) -> {
            Pair<String, XmlMetadataDataProvider> actual = a == null ? Pair.of("", null) : a;
            if (actual.getSecond() == null || !p.equals(actual.getFirst())) {
              try {
                final FilesystemMetadataResolver metadataResolver = new FilesystemMetadataResolver(new File(p));
                metadataResolver.setRequireValidMetadata(true);
                final BasicParserPool parserPool = new BasicParserPool();
                parserPool.initialize();
                metadataResolver.setParserPool(parserPool);
                metadataResolver.setId(UUID.randomUUID().toString());
                metadataResolver.initialize();
                actual = Pair.of(p, new XmlMetadataDataProvider(metadataResolver));
              } catch (ResolverException | ComponentInitializationException e) {
                throw new SAMLRuntimeException(e);
              }
            }
            return actual;
          }))
        .filter(a -> nonNull(a.getSecond()))
        .map(Pair::getSecond)
        .map(XmlMetadataDataProvider::getEntityDescriptor);
  }

  /**
   * Gets the comparison method to use for authentication context.
   * <p>
   *   If not defined, {@link AuthnContextComparisonTypeEnumeration#MINIMUM} is taken into account.
   * </p>
   * @return a {@link AuthnContextComparisonTypeEnumeration} instance.
   */
  public static AuthnContextComparisonTypeEnumeration getAuthnContextComparison(
      final HttpServletRequest httpRequest) {
    final String comparison = getSettings().getString(
        format("domain.{0}.saml.ac.comparison", getSilverpeasDomainId(httpRequest)).toLowerCase(),
        EMPTY);
    return AC_COMPARISONS.getOrDefault(comparison, MINIMUM);
  }

  /**
   * Gets the class to use for authentication context.
   * <p>
   *   If not defined, {@link AuthnContext#PASSWORD_AUTHN_CTX} is
   *   taken into account.
   * </p>
   * @return a {@link AuthnContext} constant about class.
   */
  public static String getAuthnContextClass(final HttpServletRequest httpRequest) {
    final String clazz = getSettings().getString(
        format("domain.{0}.saml.ac.class", getSilverpeasDomainId(httpRequest)).toLowerCase(),
        EMPTY);
    return AC_CLASSES.getOrDefault(clazz, PASSWORD_AUTHN_CTX);
  }

  static class XmlMetadataDataProvider {
    private final FilesystemMetadataResolver resolver;

    public XmlMetadataDataProvider(final FilesystemMetadataResolver resolver) {
      this.resolver = resolver;
    }

    EntityDescriptor getEntityDescriptor() {
      return resolver.iterator().next();
    }
  }

  static class KeystorePathData {
    private final String path;
    private final String p;
    private final String eid;
    private final String ep;

    KeystorePathData(final String domainId, final String actor) {
      this.path = getSettings().getString(
          format("domain.{0}.saml.{1}.keystore.path", domainId, actor), null);
      this.p = getSettings().getString(
          format("domain.{0}.saml.{1}.keystore.pwd", domainId, actor), null);
      this.eid = getSettings().getString(
          format("domain.{0}.saml.{1}.keystore.entryId", domainId, actor), null);
      this.ep = getSettings().getString(
          format("domain.{0}.saml.{1}.keystore.entryPwd", domainId, actor), null);
    }

    boolean isValid() {
      return isDefined(path) && isDefined(p) && isDefined(eid) && isDefined(ep);
    }

    String getPath() {
      return path;
    }

    String getPassword() {
      return p;
    }

    String getEntryId() {
      return eid;
    }

    String getEntryPassword() {
      return ep;
    }
  }

  private enum Actor {IDP, SP}
}
