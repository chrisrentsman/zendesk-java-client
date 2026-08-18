package org.zendesk.client.v2;

/**
 * {@link ZendeskException} for failures to obtain an OAuth access token.
 *
 * <p>Distinct from {@link ZendeskResponseException} so callers can tell authentication issues apart
 * from actual API exceptions.
 */
public class ZendeskOAuthException extends ZendeskException {

  private static final long serialVersionUID = 1L;

  public ZendeskOAuthException(String message) {
    super(message);
  }

  public ZendeskOAuthException(String message, Throwable cause) {
    super(message, cause);
  }
}
