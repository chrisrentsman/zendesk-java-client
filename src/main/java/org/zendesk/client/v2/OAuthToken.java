package org.zendesk.client.v2;

import java.time.Instant;

/** An immutable OAuth access token with the instants it was issued and expires. */
final class OAuthToken {

  private final String accessToken;
  private final Instant issuedAt;
  private final Instant expiresAt;

  OAuthToken(String accessToken, Instant issuedAt, Instant expiresAt) {
    this.accessToken = accessToken;
    this.issuedAt = issuedAt;
    this.expiresAt = expiresAt;
  }

  String accessToken() {
    return accessToken;
  }

  Instant issuedAt() {
    return issuedAt;
  }

  Instant expiresAt() {
    return expiresAt;
  }

  /** Does not include the access token so logging a token cannot leak the credential. */
  @Override
  public String toString() {
    return "OAuthToken{issuedAt=" + issuedAt + ", expiresAt=" + expiresAt + '}';
  }
}
