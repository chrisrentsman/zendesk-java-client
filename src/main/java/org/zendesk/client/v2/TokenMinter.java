package org.zendesk.client.v2;

/** Acquires a brand-new access token. Does no caching, no coordination and no retry. */
interface TokenMinter {

  /**
   * @throws ZendeskOAuthException if a token could not be minted
   */
  OAuthToken mint();
}
