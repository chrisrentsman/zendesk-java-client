package org.zendesk.client.v2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Request;
import org.asynchttpclient.RequestBuilder;
import org.asynchttpclient.Response;

/**
 * Mints access tokens with the OAuth {@code client_credentials} grant.
 *
 * <p>See <a href="https://developer.zendesk.com/api-reference/ticketing/oauth/grant_type_tokens/">
 * OAuth grant type tokens</a>.
 *
 * <p>Bypasses {@code Zendesk.reqBuilder} because this endpoint is at the host root, not under
 * {@code /api/v2}, and must not authenticate the call that produces its own credentials. Bypasses
 * the shared body logging because the request carries the client secret and the response the access
 * token; neither this class nor the exceptions it throws logs either.
 */
final class HttpTokenMinter implements TokenMinter {

  private static final String GRANT_TYPE = "client_credentials";
  private static final String OAUTH_TOKEN_PATH = "/oauth/tokens";

  private final AsyncHttpClient client;
  private final ObjectMapper mapper;
  private final String tokenUrl;
  private final String clientId;
  private final String clientSecret;
  private final String scope;
  private final int requestedLifetimeSeconds;
  private final Clock clock;

  HttpTokenMinter(
      AsyncHttpClient client,
      ObjectMapper mapper,
      String baseHostUrl,
      String clientId,
      String clientSecret,
      String scope,
      int requestedLifetimeSeconds,
      Clock clock) {
    this.client = client;
    this.mapper = mapper;
    this.tokenUrl = baseHostUrl + OAUTH_TOKEN_PATH;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.scope = scope;
    this.requestedLifetimeSeconds = requestedLifetimeSeconds;
    this.clock = clock;
  }

  @Override
  public OAuthToken mint() {
    Request request = buildRequest();

    // Anchor issue time before the call, so the computed expiry skews early rather than late.
    Instant issuedAt = clock.instant();

    Response response = execute(request);

    int statusCode = response.getStatusCode();
    if (statusCode < 200 || statusCode >= 300) {
      throw new ZendeskOAuthException(
          "Failed to mint an OAuth access token: HTTP/"
              + statusCode
              + " "
              + response.getStatusText());
    }

    return parseToken(response, issuedAt);
  }

  private Request buildRequest() {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("grant_type", GRANT_TYPE);
    body.put("client_id", clientId);
    body.put("client_secret", clientSecret);
    body.put("scope", scope);

    // Always set so the token lifetime is ours rather than the server default.
    body.put("expires_in", requestedLifetimeSeconds);

    byte[] serialized;
    try {
      serialized = mapper.writeValueAsBytes(body);
    } catch (IOException e) {
      // Do not include the request payload since it holds the client secret.
      throw new ZendeskOAuthException("Failed to serialize the OAuth token request", e);
    }

    return new RequestBuilder("POST")
        .setUrl(tokenUrl)
        .addHeader("Content-Type", "application/json")
        .setBody(serialized)
        .build();
  }

  private Response execute(Request request) {
    try {
      return client.executeRequest(request).get();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new ZendeskOAuthException("Interrupted while minting an OAuth access token", e);
    } catch (ExecutionException e) {
      throw new ZendeskOAuthException(
          "Failed to mint an OAuth access token: " + e.getCause(), e.getCause());
    }
  }

  private OAuthToken parseToken(Response response, Instant issuedAt) {
    JsonNode parsed;
    try {
      parsed = mapper.readTree(response.getResponseBodyAsStream());
    } catch (IOException e) {
      throw new ZendeskOAuthException("Failed to parse the OAuth token response", e);
    }

    if (parsed == null || parsed.isMissingNode()) {
      throw new ZendeskOAuthException("OAuth token response was empty");
    } else if (!parsed.isObject()) {
      throw new ZendeskOAuthException("OAuth token response was not a JSON object");
    }

    JsonNode accessToken = parsed.get("access_token");
    if (accessToken == null || !accessToken.isTextual() || accessToken.asText().trim().isEmpty()) {
      throw new ZendeskOAuthException("OAuth token response had no usable access_token");
    }

    return new OAuthToken(
        accessToken.asText(), issuedAt, issuedAt.plusSeconds(resolveLifetimeSeconds(parsed)));
  }

  private long resolveLifetimeSeconds(JsonNode parsed) {
    JsonNode grantedLifetime = parsed.get("expires_in");

    // Fallback to the requested expiry only if Zendesk did not return one.
    if (grantedLifetime == null || grantedLifetime.isNull()) {
      return requestedLifetimeSeconds;
    }

    if (!grantedLifetime.isIntegralNumber()) {
      throw new ZendeskOAuthException(
          "OAuth token response had a non-integer expires_in of type "
              + grantedLifetime.getNodeType());
    } else if (!grantedLifetime.canConvertToLong()) {
      throw new ZendeskOAuthException(
          "OAuth token response reported an out-of-range expires_in of "
              + grantedLifetime.asText());
    }

    // Guard against unusable grants: a token born expired would mean re-minting on every request,
    // and one beyond the documented maximum is not credible.
    long granted = grantedLifetime.asLong();
    if (granted <= 0 || Zendesk.Builder.MAX_OAUTH_TOKEN_LIFETIME_SECONDS < granted) {
      throw new ZendeskOAuthException(
          "OAuth token response reported an out-of-range expires_in of " + granted);
    }

    return granted;
  }
}
