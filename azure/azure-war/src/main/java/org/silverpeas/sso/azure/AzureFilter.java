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

import com.microsoft.aad.msal4j.*;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.core.UriBuilder;
import org.silverpeas.kernel.util.StringUtil;

import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static java.text.MessageFormat.format;
import static org.silverpeas.sso.azure.AuthHelper.*;
import static org.silverpeas.sso.azure.AzureLogger.getLogSessionId;
import static org.silverpeas.sso.azure.AzureLogger.logger;
import static org.silverpeas.sso.azure.settings.AzureSettings.*;

/**
 * @author silveryocha
 */
public class AzureFilter implements Filter {

  private static final String AUTHENTICATION_RESULT_WAS_NULL_MSG = "authentication result was null";
  private static final String STATES = "states";
  private static final String STATE = "state";
  private static final Integer STATE_TTL = 3600;
  private static final String FAILED_TO_VALIDATE_MESSAGE = "Failed to validate data received from" +
      " Authorization service - ";

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (request instanceof HttpServletRequest httpRequest &&
        response instanceof HttpServletResponse httpResponse) {
      try {
        // check if user has a AuthData in the session
        if (!AuthHelper.isAuthenticated(httpRequest)) {
          if (AuthHelper.containsAuthenticationData(httpRequest)) {
            logger().debug(() -> format(
                "Back to azure authority server with authentication data for session {0}.",
                getLogSessionId(httpRequest)));
            processAuthenticationData(httpRequest);
          } else {
            // not authenticated
            logger().debug(() -> format("Going to azure authority server for session {0}.",
                getLogSessionId(httpRequest)));
            sendAuthRedirect(httpRequest, httpResponse);
            return;
          }
        }
        if (isAuthDataExpired(httpRequest)) {
          updateAuthDataSilently(httpRequest);
        }
      } catch (MsalException msalException) {
        // something went wrong (like expiration or revocation of token)
        // we should invalidate AuthData stored in session and redirect to Authorization server
        invalidateAuth(httpRequest);
        logger().debug(() -> format("Due to authentication error, going to azure authority server" +
                " for session {0}.",
            getLogSessionId(httpRequest)));
        sendAuthRedirect(httpRequest, httpResponse);
        return;
      } catch (Exception e) {
        logger().error(e);
        httpResponse.setStatus(500);
      }
    }
    chain.doFilter(request, response);
  }

  private boolean isAuthDataExpired(HttpServletRequest httpRequest) {
    final IAuthenticationResult authData = getAuthSessionObject(httpRequest);
    return authData != null && authData.expiresOnDate().before(new Date());
  }

  /**
   * Silently renews the access token from MSAL's token cache (which holds the refresh token). On
   * any MSAL failure (e.g. interaction required) the {@link MsalException} is propagated so that
   * the filter can fall back to an interactive redirect to the authority server.
   */
  private void updateAuthDataSilently(HttpServletRequest httpRequest)
      throws ServletException, MsalException {
    final SessionTokenCacheAspect cacheAspect =
        new SessionTokenCacheAspect(getTokenCache(httpRequest));
    final ConfidentialClientApplication app = buildClient(cacheAspect);
    final Set<IAccount> accounts = app.getAccounts().join();
    if (accounts.isEmpty()) {
      throw new MsalClientException("No account in MSAL token cache for silent token renewal",
          "no_account_in_cache");
    }
    final SilentParameters params =
        SilentParameters.builder(getScopes(), accounts.iterator().next()).build();
    final IAuthenticationResult authData;
    try {
      authData = app.acquireTokenSilently(params).get();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new ServletException(e);
    } catch (ExecutionException e) {
      if (e.getCause() instanceof MsalException msalException) {
        throw msalException;
      }
      throw new ServletException(e.getCause() != null ? e.getCause() : e);
    } catch (MalformedURLException e) {
      throw new ServletException(e);
    }
    setSessionPrincipal(httpRequest, authData);
    setSessionTokenCache(httpRequest, cacheAspect.getSerializedCache());
    logger().debug(() -> format(
        "Access token refreshed for principal {1} on session {0}.",
        getLogSessionId(httpRequest), authData.account().username()));
  }

  private void processAuthenticationData(HttpServletRequest httpRequest)
      throws ServletException {
    final Map<String, List<String>> params = httpRequest.getParameterMap().entrySet().stream()
        .collect(
            Collectors.toMap(Map.Entry::getKey, e -> Arrays.asList(e.getValue())));

    // validate that state in response equals to state in request
    final StateData stateData = validateState(httpRequest.getSession(false),
        params.get(STATE).get(0));

    final String currentUri = httpRequest.getRequestURL().toString();
    final AuthenticationResponse authResponse;
    try {
      authResponse = AuthenticationResponseParser.parse(getFullCurrentUri(httpRequest,
          currentUri), params);
    } catch (ParseException e) {
      throw new ServletException(e);
    }
    if (isAuthenticationSuccessful(authResponse)) {
      AuthenticationSuccessResponse oidcResponse = (AuthenticationSuccessResponse) authResponse;

      // validate that OIDC Auth Response matches Code Flow (contains only requested artifacts)
      validateAuthRespMatchesCodeFlow(oidcResponse);

      // Getting access token
      final IAuthenticationResult authData =
          getAccessToken(oidcResponse.getAuthorizationCode(), currentUri, httpRequest);

      // validate nonce to prevent reply attacks (code maybe substituted to one with broader access)
      validateNonce(stateData, getClaimValueFromIdToken(authData.idToken(), "nonce"));

      // successful authentication
      setSessionPrincipal(httpRequest, authData);

      logger().debug(
          () -> format("Successful access token get. Principal {1} identified for session {0}.",
              getLogSessionId(httpRequest), authData.account().username()));
    } else {
      AuthenticationErrorResponse oidcResponse = (AuthenticationErrorResponse) authResponse;
      logger().debug(() -> format(
          "Authentication is in error for session {0} [code: {1}, description: {2}].",
          getLogSessionId(httpRequest), oidcResponse.getErrorObject().getCode(),
          oidcResponse.getErrorObject().getDescription()));
      throw new ServletException(String.format("Request for auth code failed: %s - %s",
          oidcResponse.getErrorObject().getCode(),
          oidcResponse.getErrorObject().getDescription()));
    }
  }

  private URI getFullCurrentUri(final HttpServletRequest httpRequest, final String currentUri) {
    return UriBuilder.fromUri(currentUri +
        (httpRequest.getQueryString() != null ? "?" + httpRequest.getQueryString() : "")).build();
  }

  /**
   * make sure that state is stored in the session, delete it from session - should be used only
   * once
   *
   * @param session the current session
   * @param state the state value.
   * @throws ServletException on technical error.
   */
  private StateData validateState(HttpSession session, String state) throws ServletException {
    if (StringUtil.isDefined(state)) {
      final StateData stateDataInSession = removeStateFromSession(session, state);
      if (stateDataInSession != null) {
        return stateDataInSession;
      }
    }
    throw new ServletException(FAILED_TO_VALIDATE_MESSAGE + "could not validate state");
  }

  @SuppressWarnings("unchecked")
  private StateData removeStateFromSession(HttpSession session, String state) {
    final Map<String, StateData> states = session != null ?
        (Map<String, StateData>) session.getAttribute(STATES) : null;
    if (states != null) {
      eliminateExpiredStates(states);
      final StateData stateData = states.get(state);
      if (stateData != null) {
        states.remove(state);
        return stateData;
      }
    }
    return null;
  }

  private void validateAuthRespMatchesCodeFlow(AuthenticationSuccessResponse oidcResponse)
      throws ServletException {
    if (oidcResponse.getIDToken() != null || oidcResponse.getAccessToken() != null ||
        oidcResponse.getAuthorizationCode() == null) {
      throw new ServletException(
          FAILED_TO_VALIDATE_MESSAGE + "unexpected set of artifacts received");
    }
  }

  private void validateNonce(StateData stateData, String nonce) throws ServletException {
    if (StringUtil.isNotDefined(nonce) || !nonce.equals(stateData.nonce())) {
      throw new ServletException(FAILED_TO_VALIDATE_MESSAGE + "could not validate nonce");
    }
  }

  @SuppressWarnings("SameParameterValue")
  private String getClaimValueFromIdToken(String idToken, String claimKey)
      throws ServletException {
    try {
      return (String) JWTParser.parse(idToken).getJWTClaimsSet().getClaim(claimKey);
    } catch (java.text.ParseException e) {
      throw new ServletException(e);
    }
  }

  private void setSessionPrincipal(HttpServletRequest httpRequest, IAuthenticationResult result) {
    httpRequest.getSession().setAttribute(PRINCIPAL_ATTRIBUTE_NAME, result);
  }

  private void setSessionTokenCache(HttpServletRequest httpRequest, String serializedCache) {
    httpRequest.getSession().setAttribute(TOKEN_CACHE_ATTRIBUTE_NAME, serializedCache);
  }

  private void sendAuthRedirect(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
      throws IOException, ServletException {
    httpResponse.setStatus(302);

    // use state parameter to validate response from Authorization server
    final String state = UUID.randomUUID().toString();

    // use nonce parameter to validate idToken
    final String nonce = UUID.randomUUID().toString();

    storeStateInSession(httpRequest.getSession(), state, nonce);

    final String currentUri = httpRequest.getRequestURL().toString();

    httpResponse.sendRedirect(getRedirectUrl(currentUri, httpRequest.getParameter("claims"),
        state, nonce));
  }

  private void eliminateExpiredStates(Map<String, StateData> map) {
    final Date currentTime = new Date();
    map.entrySet().removeIf(e -> {
      final long diffInSeconds = TimeUnit.MILLISECONDS.
          toSeconds(currentTime.getTime() - e.getValue().expirationDate().getTime());
      return diffInSeconds > STATE_TTL;
    });
  }

  @SuppressWarnings("unchecked")
  private void storeStateInSession(HttpSession session, String state, String nonce) {
    Map<String, StateData> states = (Map<String, StateData>) session.getAttribute(STATES);
    if (states == null) {
      states = new HashMap<>();
      session.setAttribute(STATES, states);
    }
    states.put(state, new StateData(nonce, new Date()));
  }

  @Override
  public void destroy() {
    // nothing to do
  }

  @Override
  public void init(final FilterConfig filterConfig) {
    // nothing to do
  }

  private IAuthenticationResult getAccessToken(AuthorizationCode authorizationCode,
      String currentUri, HttpServletRequest httpRequest) throws ServletException {
    final SessionTokenCacheAspect cacheAspect =
        new SessionTokenCacheAspect(getTokenCache(httpRequest));
    final ConfidentialClientApplication app = buildClient(cacheAspect);
    final IAuthenticationResult result;
    try {
      final AuthorizationCodeParameters parameters = AuthorizationCodeParameters
          .builder(authorizationCode.getValue(), new URI(currentUri))
          .scopes(getScopes())
          .build();
      result = app.acquireToken(parameters).get();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new ServletException(e);
    } catch (ExecutionException e) {
      throw new ServletException(e.getCause() != null ? e.getCause() : e);
    } catch (URISyntaxException e) {
      throw new ServletException(e);
    }
    if (result == null) {
      throw new ServletException(AUTHENTICATION_RESULT_WAS_NULL_MSG);
    }
    setSessionTokenCache(httpRequest, cacheAspect.getSerializedCache());
    return result;
  }

  private ConfidentialClientApplication buildClient(SessionTokenCacheAspect cacheAspect)
      throws ServletException {
    try {
      final IClientCredential credential =
          ClientCredentialFactory.createFromSecret(getClientSecretKey());
      final ConfidentialClientApplication.Builder builder =
          ConfidentialClientApplication.builder(getClientId(), credential)
              .authority(getTenantAuthorityPath());
      if (cacheAspect != null) {
        builder.setTokenCacheAccessAspect(cacheAspect);
      }
      return builder.build();
    } catch (MalformedURLException e) {
      throw new ServletException(e);
    }
  }

  private String getRedirectUrl(String currentUri, String claims, String state, String nonce)
      throws ServletException {
    final ConfidentialClientApplication app = buildClient(null);
    final AuthorizationRequestUrlParameters.Builder builder = AuthorizationRequestUrlParameters
        .builder(currentUri, getScopes())
        .state(state)
        .nonce(nonce);
    if (StringUtil.isDefined(claims)) {
      builder.claimsChallenge(claims);
    }
    return app.getAuthorizationRequestUrl(builder.build()).toString();
  }

  private record StateData(String nonce, Date expirationDate) implements Serializable {
      @Serial
      private static final long serialVersionUID = 123456333519529362L;

  }
}
