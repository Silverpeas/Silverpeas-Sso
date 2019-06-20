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

package org.silverpeas.sso.azure;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationException;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.silverpeas.core.util.StringUtil;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
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
  private static final String FAILED_TO_VALIDATE_MESSAGE = "Failed to validate data received from Authorization service - ";

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (request instanceof HttpServletRequest) {
      final HttpServletRequest httpRequest = (HttpServletRequest) request;
      final HttpServletResponse httpResponse = (HttpServletResponse) response;
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
          updateAuthDataUsingRefreshToken(httpRequest);
        }
      } catch (AuthenticationException authException) {
        // something went wrong (like expiration or revocation of token)
        // we should invalidate AuthData stored in session and redirect to Authorization server
        invalidateAuth(httpRequest);
        logger().debug(() -> format("Due to authentication error, going to azure authority server for session {0}.",
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
    final AuthenticationResult authData = getAuthSessionObject(httpRequest);
    return authData != null && authData.getExpiresOnDate().before(new Date());
  }

  private void updateAuthDataUsingRefreshToken(HttpServletRequest httpRequest) throws ServletException {
    final String refreshToken = getAuthSessionObject(httpRequest).getRefreshToken();
    final AuthenticationResult authData = getAccessTokenFromRefreshToken(refreshToken);
    setSessionPrincipal(httpRequest, authData);
    logger().debug(() -> format(
        "Access token refreshed for principal {1} on session {0}.",
        getLogSessionId(httpRequest), authData.getUserInfo().getDisplayableId()));
  }

  private void processAuthenticationData(HttpServletRequest httpRequest)
      throws ServletException {
    final Map<String, String> params = httpRequest.getParameterMap().entrySet().stream()
        .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue()[0]));

    // validate that state in response equals to state in request
    final StateData stateData = validateState(httpRequest.getSession(false), params.get(STATE));

    final String currentUri = httpRequest.getRequestURL().toString();
    final AuthenticationResponse authResponse;
    try {
      authResponse = AuthenticationResponseParser.parse(getFullCurrentUri(httpRequest, currentUri), params);
    } catch (ParseException e) {
      throw new ServletException(e);
    }
    if (isAuthenticationSuccessful(authResponse)) {
      AuthenticationSuccessResponse oidcResponse = (AuthenticationSuccessResponse) authResponse;

      // validate that OIDC Auth Response matches Code Flow (contains only requested artifacts)
      validateAuthRespMatchesCodeFlow(oidcResponse);

      // Getting access token
      final AuthenticationResult authData = getAccessToken(oidcResponse.getAuthorizationCode(), currentUri);

      // validate nonce to prevent reply attacks (code maybe substituted to one with broader access)
      validateNonce(stateData, getClaimValueFromIdToken(authData.getIdToken(), "nonce"));

      // successful authentication
      setSessionPrincipal(httpRequest, authData);

      logger().debug(
          () -> format("Successful access token get. Principal {1} identified for session {0}.",
              getLogSessionId(httpRequest), authData.getUserInfo().getDisplayableId()));
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
   * make sure that state is stored in the session,
   * delete it from session - should be used only once
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
    final Map<String, StateData> states =  session != null ? (Map<String, StateData>) session.getAttribute(STATES) : null;
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
    if (StringUtil.isNotDefined(nonce) || !nonce.equals(stateData.getNonce())) {
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

  private void setSessionPrincipal(HttpServletRequest httpRequest, AuthenticationResult result) {
    httpRequest.getSession().setAttribute(PRINCIPAL_ATTRIBUTE_NAME, result);
  }

  private void sendAuthRedirect(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException {
    httpResponse.setStatus(302);

    // use state parameter to validate response from Authorization server
    final String state = UUID.randomUUID().toString();

    // use nonce parameter to validate idToken
    final String nonce = UUID.randomUUID().toString();

    storeStateInSession(httpRequest.getSession(), state, nonce);

    final String currentUri = httpRequest.getRequestURL().toString();

    httpResponse.sendRedirect(getRedirectUrl(currentUri, httpRequest.getParameter("claims"), state, nonce));
  }

  private void eliminateExpiredStates(Map<String, StateData> map) {
    final Date currentTime = new Date();
    map.entrySet().removeIf(e -> {
      final long diffInSeconds = TimeUnit.MILLISECONDS.
          toSeconds(currentTime.getTime() - e.getValue().getExpirationDate().getTime());
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

  private AuthenticationResult getAccessTokenFromRefreshToken(String refreshToken)
      throws ServletException {
    return performAccessTokenRequest(
        c -> c.acquireTokenByRefreshToken(refreshToken, getClientCredential(), null, null));
  }

  private AuthenticationResult getAccessToken(AuthorizationCode authorizationCode,
      String currentUri) throws ServletException {
    final String authCode = authorizationCode.getValue();
    final ClientCredential credential = getClientCredential();
    return performAccessTokenRequest(
        c -> c.acquireTokenByAuthorizationCode(authCode, UriBuilder.fromUri(currentUri).build(),
            credential, null));
  }

  private AuthenticationResult performAccessTokenRequest(
      Function<AuthenticationContext, Future<AuthenticationResult>> process)
      throws ServletException {
    AuthenticationResult result;
    ExecutorService service = null;
    try {
      service = Executors.newFixedThreadPool(1);
      AuthenticationContext context = new AuthenticationContext(getTenantAuthorityPath(), true, service);
      result = process.apply(context).get();
    } catch (ExecutionException | MalformedURLException | InterruptedException e) {
      throw new ServletException(e.getCause());
    } finally {
      if (service != null) {
        service.shutdown();
      }
    }

    if (result == null) {
      throw new ServletException(AUTHENTICATION_RESULT_WAS_NULL_MSG);
    }
    return result;
  }

  private ClientCredential getClientCredential() {
    return new ClientCredential(getClientId(), getClientSecretKey());
  }

  private static String getRedirectUrl(String currentUri, String claims, String state, String nonce) {
    final UriBuilder builder = UriBuilder
        .fromPath(getTenantAuthorityPath()).path("oauth2/authorize")
        .queryParam("response_type", "code")
        .queryParam("response_mode", "form_post")
        .queryParam("redirect_uri", currentUri)
        .queryParam("client_id", getClientId())
        .queryParam("resource", "https://graph.windows.net")
        .queryParam(STATE, state)
        .queryParam("nonce",nonce);
    if (StringUtil.isDefined(claims)) {
      builder.queryParam("claims", claims);
    }
    return builder.build().toString();
  }

  private static class StateData implements Serializable {
    private static final long serialVersionUID = 123456333519529362L;

    private String nonce;
    private Date expirationDate;

    StateData(String nonce, Date expirationDate) {
      this.nonce = nonce;
      this.expirationDate = expirationDate;
    }

    String getNonce() {
      return nonce;
    }

    Date getExpirationDate() {
      return expirationDate;
    }
  }
}