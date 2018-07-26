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

package org.silverpeas.sso.saml;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.messaging.handler.impl.BasicMessageHandlerChain;
import org.opensaml.messaging.pipeline.httpclient.BasicHttpClientMessagePipeline;
import org.opensaml.messaging.pipeline.httpclient.HttpClientMessagePipeline;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.SAMLOutboundProtocolMessageSigningHandler;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLMessageInfoContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HttpClientResponseSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HttpClientRequestSOAP11Encoder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.soap.client.http.AbstractPipelineHttpSOAPClient;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.silverpeas.core.SilverpeasRuntimeException;

import javax.annotation.Nonnull;
import javax.security.auth.message.AuthException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.StringReader;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static java.text.MessageFormat.format;
import static org.silverpeas.core.util.StringUtil.*;
import static org.silverpeas.sso.saml.OpenSamlUtils.buildSamlObject;
import static org.silverpeas.sso.saml.OpenSamlUtils.logSamlObject;
import static org.silverpeas.sso.saml.SamlAuthHelper.invalidateAuth;
import static org.silverpeas.sso.saml.SamlAuthHelper.setSessionPrincipal;
import static org.silverpeas.sso.saml.SamlLogger.getLogSessionId;
import static org.silverpeas.sso.saml.SamlLogger.logger;
import static org.silverpeas.sso.saml.settings.SamlSettings.*;

/**
 * @author silveryocha
 */
public class SamlFilter implements Filter {

  @SuppressWarnings("ConstantConditions")
  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    if (request instanceof HttpServletRequest) {
      final HttpServletRequest httpRequest = (HttpServletRequest) request;
      final HttpServletResponse httpResponse = (HttpServletResponse) response;

      try {
        // check if user has a AuthData in the session
        if (!SamlAuthHelper.isAuthenticated(httpRequest)) {
          final SamlContext context = new SamlContext(httpRequest, httpResponse);
          if (redirectUserForAuthentication(context)) {
            return;
          }
          performSamlArtifactResolve(context);
          performSamlRequest(context);
          performSamlResponse(context);
        }
      } catch (AuthException | SignatureException fe) {
        // something went wrong (like expiration or revocation of token)
        // we should invalidate AuthData stored in session and redirect to Authorization server
        invalidateAuth(httpRequest);
        logger().debug(() -> format(
            "Due to authentication error, going to Saml SSO URL server for session {0}.",
            getLogSessionId(httpRequest)));
      } catch (Exception e) {
        logger().error(e);
        httpResponse.setStatus(500);
      }
    }
    chain.doFilter(request, response);
  }

  private void performSamlArtifactResolve(final SamlContext context)
      throws AuthException, SignatureException {
    final Optional<String> optionalArtifactResolve = context.getArtifactResolve();
    if (optionalArtifactResolve.isPresent()) {
      if (isNotDefined(getArtifactResolutionServiceUrl(context.getHttpRequest()))) {
        throw new SilverpeasRuntimeException(
            format("URL of artifact resolution service is not defined for domain {0}",
                getSilverpeasDomainId(context.getHttpRequest())));
      }
      logger().debug("Artifact received");
      final Artifact artifact = buildArtifactFromRequest(optionalArtifactResolve.get());
      logger().debug("Artifact: " + artifact.getArtifact());
      final ArtifactResolve artifactResolve = buildArtifactResolve(context, artifact);
      logger().debug("Sending ArtifactResolve");
      logger().debug("ArtifactResolve: ");
      logSamlObject(artifactResolve);
      ArtifactResponse artifactResponse = sendAndReceiveArtifactResolve(context, artifactResolve);
      logger().debug("ArtifactResponse received");
      logger().debug("ArtifactResponse: ");
      logSamlObject(artifactResponse);
      validateDestinationAndLifetime(context, artifactResponse);
      EncryptedAssertion encryptedAssertion = getEncryptedAssertion(artifactResponse);
      Assertion assertion = decryptAssertion(encryptedAssertion);
      validateAssertion(context, assertion);
      logger().debug("Decrypted Assertion: ");
      logSamlObject(assertion);
    }
  }

  private Artifact buildArtifactFromRequest(final String artifactResolve) {
    Artifact artifact = buildSamlObject(Artifact.class);
    artifact.setArtifact(artifactResolve);
    return artifact;
  }

  private ArtifactResolve buildArtifactResolve(final SamlContext context, final Artifact artifact) {
    final ArtifactResolve artifactResolve = buildSamlObject(ArtifactResolve.class);
    Issuer issuer = buildSamlObject(Issuer.class);
    issuer.setValue(getEntityId(context.getHttpRequest()));
    artifactResolve.setIssuer(issuer);
    artifactResolve.setIssueInstant(DateTime.now());
    artifactResolve.setID(OpenSamlUtils.generateSecureRandomId());
    artifactResolve.setDestination(getArtifactResolutionServiceUrl(context.getHttpRequest()));
    artifactResolve.setArtifact(artifact);
    return artifactResolve;
  }

  @SuppressWarnings("unchecked")
  private ArtifactResponse sendAndReceiveArtifactResolve(final SamlContext context,
      final ArtifactResolve artifactResolve) {
    try {
      final MessageContext<ArtifactResolve> contextOut = new MessageContext<>();
      contextOut.setMessage(artifactResolve);
      final InOutOperationContext<ArtifactResponse, ArtifactResolve> opContext = new
          ProfileRequestContext<>();
      opContext.setOutboundMessageContext(contextOut);
      final AbstractPipelineHttpSOAPClient<SAMLObject, SAMLObject> soapClient = new
          AbstractPipelineHttpSOAPClient() {
        @Override
        @Nonnull
        protected HttpClientMessagePipeline newPipeline() {
          final HttpClientRequestSOAP11Encoder encoder = new HttpClientRequestSOAP11Encoder();
          final HttpClientResponseSOAP11Decoder decoder = new HttpClientResponseSOAP11Decoder();
          final BasicHttpClientMessagePipeline pipeline = new BasicHttpClientMessagePipeline(
              encoder, decoder);
          pipeline.setOutboundPayloadHandler(new SAMLOutboundProtocolMessageSigningHandler());
          return pipeline;
        }
      };
      final HttpClientBuilder clientBuilder = new HttpClientBuilder();
      soapClient.setHttpClient(clientBuilder.buildClient());
      soapClient.send(getArtifactResolutionServiceUrl(context.getHttpRequest()), opContext);
      return opContext.getInboundMessageContext().getMessage();
    } catch (Exception e) {
      throw new SilverpeasRuntimeException(e);
    }
  }

  @SuppressWarnings({"unchecked", "ConstantConditions"})
  private void validateDestinationAndLifetime(final SamlContext context,
      final ArtifactResponse artifactResponse) {
    final MessageContext msgContext = new MessageContext<ArtifactResponse>();
    msgContext.setMessage(artifactResponse);
    final SAMLMessageInfoContext messageInfoContext = msgContext
        .getSubcontext(SAMLMessageInfoContext.class, true);
    messageInfoContext.setMessageIssueInstant(artifactResponse.getIssueInstant());
    final MessageLifetimeSecurityHandler lifetimeSecurityHandler = new
        MessageLifetimeSecurityHandler();
    lifetimeSecurityHandler.setClockSkew(1000);
    lifetimeSecurityHandler.setMessageLifetime(2000);
    lifetimeSecurityHandler.setRequiredRule(true);
    final ReceivedEndpointSecurityHandler receivedEndpointSecurityHandler = new
        ReceivedEndpointSecurityHandler();
    receivedEndpointSecurityHandler.setHttpServletRequest(context.getHttpRequest());
    final List<MessageHandler<ArtifactResponse>> handlers = new ArrayList<>();
    handlers.add(lifetimeSecurityHandler);
    handlers.add(receivedEndpointSecurityHandler);
    final BasicMessageHandlerChain<ArtifactResponse> handlerChain = new
        BasicMessageHandlerChain<>();
    handlerChain.setHandlers(handlers);
    try {
      handlerChain.initialize();
      handlerChain.doInvoke(msgContext);
    } catch (ComponentInitializationException | MessageHandlerException e) {
      throw new SilverpeasRuntimeException(e);
    }
  }

  private EncryptedAssertion getEncryptedAssertion(final ArtifactResponse artifactResponse) {
    Response response = (Response) artifactResponse.getMessage();
    return response.getEncryptedAssertions().get(0);
  }

  private Assertion decryptAssertion(final EncryptedAssertion encryptedAssertion) {
    final Decrypter decrypter = new Decrypter(null, null, new InlineEncryptedKeyResolver());
    decrypter.setRootInNewDocument(true);
    try {
      return decrypter.decrypt(encryptedAssertion);
    } catch (DecryptionException e) {
      throw new SilverpeasRuntimeException(e);
    }
  }

  private void performSamlRequest(final SamlContext context) {
    if (context.getSamlRequest().isPresent()) {
      logger().debug(() -> format("Processing SAML request for session {0}.",
          getLogSessionId(context.getHttpRequest())));
      logger().debug(
          () -> format("Nothing done for now {0}.", getLogSessionId(context.getHttpRequest())));
    }
  }

  private void performSamlResponse(final SamlContext context)
      throws AuthException, SignatureException {
    final Optional<String> samlResponse = context.getSamlResponse();
    if (samlResponse.isPresent()) {
      final Assertion assertion = getSamlAssertion(samlResponse.get());
      validateAssertion(context, assertion);
    }
  }

  private boolean redirectUserForAuthentication(final SamlContext context) {
    boolean performed = false;
    if (!context.getArtifactResolve().isPresent() && !context.getSamlRequest().isPresent() &&
        !context.getSamlResponse().isPresent()) {
      // not authenticated
      logger().debug(() -> format("Going to saml SSO URL for session {0}.",
          getLogSessionId(context.getHttpRequest())));
      final AuthnRequest authnRequest = buildAuthnRequest(context);
      redirectUserWithRequest(context, authnRequest);
      performed = true;
    }
    return performed;
  }

  private AuthnRequest buildAuthnRequest(final SamlContext context) {
    final AuthnRequest authnRequest = buildSamlObject(AuthnRequest.class);
    authnRequest.setIssueInstant(DateTime.now());
    authnRequest.setDestination(getSsoServiceUrl(context.getHttpRequest()));
    authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
    authnRequest
        .setAssertionConsumerServiceURL(getAssertionConsumerServiceUrl(context.getHttpRequest()));
    authnRequest.setID(OpenSamlUtils.generateSecureRandomId());
    authnRequest.setIssuer(buildIssuer(context));
    authnRequest.setNameIDPolicy(buildNameIdPolicy());
    authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext());
    return authnRequest;
  }

  private Issuer buildIssuer(final SamlContext context) {
    final Issuer issuer = buildSamlObject(Issuer.class);
    issuer.setValue(getEntityId(context.getHttpRequest()));
    return issuer;
  }

  private NameIDPolicy buildNameIdPolicy() {
    final NameIDPolicy nameIDPolicy = buildSamlObject(NameIDPolicy.class);
    nameIDPolicy.setAllowCreate(false);
    nameIDPolicy.setFormat(NameIDType.TRANSIENT);
    return nameIDPolicy;
  }

  private RequestedAuthnContext buildRequestedAuthnContext() {
    final RequestedAuthnContext requestedAuthnContext = buildSamlObject(
        RequestedAuthnContext.class);
    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
    final AuthnContextClassRef passwordAuthnContextClassRef = buildSamlObject(
        AuthnContextClassRef.class);
    passwordAuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
    requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);
    return requestedAuthnContext;

  }

  @SuppressWarnings({"unchecked", "ConstantConditions"})
  private void redirectUserWithRequest(final SamlContext context, final AuthnRequest authnRequest) {
    final MessageContext msgContext = new MessageContext();
    msgContext.setMessage(authnRequest);
    final SAMLPeerEntityContext peerEntityContext = msgContext
        .getSubcontext(SAMLPeerEntityContext.class, true);
    final SAMLEndpointContext endpointContext = peerEntityContext
        .getSubcontext(SAMLEndpointContext.class, true);
    endpointContext.setEndpoint(getIdpEndpoint(context));
    final HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
    encoder.setMessageContext(msgContext);
    encoder.setHttpServletResponse(context.getHttpResponse());
    try {
      encoder.initialize();
    } catch (ComponentInitializationException e) {
      throw new SilverpeasRuntimeException(e);
    }
    logger().debug("AuthnRequest: ");
    logSamlObject(authnRequest);
    logger().info("Redirecting to IDP");
    try {
      encoder.encode();
    } catch (MessageEncodingException e) {
      throw new SilverpeasRuntimeException(e);
    }
  }

  private Endpoint getIdpEndpoint(final SamlContext context) {
    SingleSignOnService endpoint = buildSamlObject(SingleSignOnService.class);
    endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    endpoint.setLocation(getSsoServiceUrl(context.getHttpRequest()));
    return endpoint;
  }

  @SuppressWarnings("ConstantConditions")
  private void validateSignature(final SamlContext context, final Assertion assertion)
      throws SignatureException {
    final Signature signature = assertion.getSignature();
    final SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
    profileValidator.validate(signature);
    SignatureValidator.validate(signature, getIdpCredential(context.getHttpRequest()));
  }

  private void validateAssertion(final SamlContext context, final Assertion assertion)
      throws SignatureException, AuthException {
    logger().debug(() -> format("Processing SAML response for session {0}.",
        getLogSessionId(context.getHttpRequest())));
    validateSignature(context, assertion);
    validateDelay(assertion);
    validatePrincipal(context, assertion);
  }

  private void validateDelay(final Assertion assertion) throws AuthException {
    final DateTime notOnOrAfter = assertion.getConditions().getNotOnOrAfter();
    if (notOnOrAfter != null && !notOnOrAfter.isAfterNow()) {
      throw new AuthException("delay expired");
    }
  }

  private void validatePrincipal(final SamlContext context, final Assertion assertion)
      throws AuthException {
    final String principal = assertion.getSubject().getNameID().getValue();
    if (isNotDefined(principal)) {
      throw new AuthException("no principal detected");
    }
    setSessionPrincipal(context.getHttpRequest(), principal);
  }

  @SuppressWarnings("ConstantConditions")
  private Assertion getSamlAssertion(final String samlAsXml) throws AuthException {
    try {
      final XMLObject xmlObj = XMLObjectSupport
          .unmarshallFromReader(XMLObjectProviderRegistrySupport.getParserPool(),
              new StringReader(samlAsXml));
      final Response response = (Response) xmlObj;
      return response.getAssertions().get(0);
    } catch (Exception e) {
      logger().error(e);
      throw new AuthException(e.getMessage());
    }
  }

  @Override
  public void init(final FilterConfig filterConfig) throws ServletException {
    try {
      final JavaCryptoValidationInitializer javaCryptoValidationInitializer = new
          JavaCryptoValidationInitializer();
      javaCryptoValidationInitializer.init();
    } catch (InitializationException e) {
      throw new ServletException(e);
    }
    logger().info("Security providers:");
    for (Provider jceProvider : Security.getProviders()) {
      logger().info("\t{0}", jceProvider.getInfo());
    }
    try {
      InitializationService.initialize();
    } catch (Exception e) {
      logger().error(e);
      throw new ServletException(e);
    }
  }

  @Override
  public void destroy() {
    // nothing to do
  }

  private static class SamlContext {
    private final HttpServletRequest httpRequest;
    private final HttpServletResponse httpResponse;
    private String artifactResolve = null;
    private String samlRequest = null;
    private String samlResponse = null;

    SamlContext(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse) {
      this.httpRequest = httpRequest;
      this.httpResponse = httpResponse;
      decodeParameters();
    }

    private void decodeParameters() {
      artifactResolve = defaultStringIfNotDefined(httpRequest.getParameter("SAMLart"), null);
      samlRequest = defaultStringIfNotDefined(httpRequest.getParameter("SAMLRequest"), null);
      samlResponse = defaultStringIfNotDefined(httpRequest.getParameter("SAMLResponse"), null);
    }

    HttpServletRequest getHttpRequest() {
      return httpRequest;
    }

    HttpServletResponse getHttpResponse() {
      return httpResponse;
    }

    Optional<String> getArtifactResolve() {
      return Optional.ofNullable(artifactResolve);
    }

    Optional<String> getSamlRequest() {
      return Optional.ofNullable(samlRequest);
    }

    Optional<String> getSamlResponse() {
      return Optional.ofNullable(samlResponse != null ? new String(fromBase64(samlResponse)) : null);
    }
  }
}
