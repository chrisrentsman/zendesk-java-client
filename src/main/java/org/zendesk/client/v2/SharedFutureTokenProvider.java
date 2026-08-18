package org.zendesk.client.v2;

import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Caches an access token and keeps it fresh, allowing only one mint in flight at a time. A fresh
 * token is read lock-free; a stale but unexpired one keeps being served while one thread refreshes
 * it; threads left with nothing usable await that mint and share its outcome, success or failure.
 *
 * <p>Refresh is single-flight but synchronous: the elected thread performs the mint before
 * returning, even when its previous token is still valid.
 *
 * <p>Two invariants a future change must preserve:
 *
 * <ol>
 *   <li>The {@code synchronized} block decides only who mints; the mint runs outside it, so threads
 *       never queue behind a network round trip.
 *   <li>Both fallback paths re-check freshness against the live clock via {@link #isServable},
 *       never a verdict captured earlier, so a token that expires <em>during</em> a mint is not
 *       handed out.
 * </ol>
 */
final class SharedFutureTokenProvider implements TokenProvider {

  private final TokenMinter minter;
  private final Clock clock;
  private final double refreshThreshold;

  /** Read lock-free on the hot path; the token is immutable, so publication is safe. */
  private final AtomicReference<OAuthToken> currentToken = new AtomicReference<>();

  private final Object lock = new Object();

  /** Null when no refresh is in progress. Guarded by {@link #lock}. */
  private CompletableFuture<OAuthToken> inFlightRefresh;

  SharedFutureTokenProvider(TokenMinter minter, Clock clock, double refreshThreshold) {
    if (!(refreshThreshold > 0.0 && refreshThreshold < 1.0)) {
      throw new IllegalArgumentException(
          "refreshThreshold must be between 0 and 1 exclusive, but was " + refreshThreshold);
    }
    this.minter = minter;
    this.clock = clock;
    this.refreshThreshold = refreshThreshold;
  }

  @Override
  public String provideBearerToken() {
    OAuthToken token = currentToken.get();
    if (token != null && isFresh(token)) {
      return token.accessToken();
    }

    // Elect the refreshing thread.
    CompletableFuture<OAuthToken> refreshRound;
    boolean isLeader;
    synchronized (lock) {
      if (inFlightRefresh != null) {
        refreshRound = inFlightRefresh;
        isLeader = false;
      } else {
        refreshRound = inFlightRefresh = new CompletableFuture<>();
        isLeader = true;
      }
    }

    if (isLeader) {
      return mintAsLeader(refreshRound);
    } else if (isServable(clock, token)) {
      return token.accessToken();
    } else {
      return await(refreshRound);
    }
  }

  private String mintAsLeader(CompletableFuture<OAuthToken> refreshRound) {
    try {
      // If another thread has already refreshed, just use that result.
      OAuthToken refreshedByPeer = currentToken.get();
      if (refreshedByPeer != null && isFresh(refreshedByPeer)) {
        refreshRound.complete(refreshedByPeer);
        return refreshedByPeer.accessToken();
      }

      // Ensure we publish the token before completing the round.
      OAuthToken minted = minter.mint();
      currentToken.set(minted);
      refreshRound.complete(minted);
      return minted.accessToken();
    } catch (RuntimeException e) {
      // The round fails for every awaiting thread, all sharing this exception.
      // This thread can still continue if the cached token has not expired yet.
      refreshRound.completeExceptionally(e);
      OAuthToken fallback = currentToken.get();
      if (isServable(clock, fallback)) {
        return fallback.accessToken();
      }
      throw e;
    } finally {
      // Clear out the slot so that the next refresh can run when needed, and ensure
      // that the round completes if no other path has done it yet. Otherwise, its
      // waiting threads will block indefinitely.
      synchronized (lock) {
        inFlightRefresh = null;
      }

      if (!refreshRound.isDone()) {
        refreshRound.completeExceptionally(
            new ZendeskOAuthException("OAuth token refresh did not complete"));
      }
    }
  }

  private boolean isFresh(OAuthToken token) {
    long lifetimeMillis = Duration.between(token.issuedAt(), token.expiresAt()).toMillis();
    long remainingMillis = Duration.between(clock.instant(), token.expiresAt()).toMillis();
    return remainingMillis > (long) (lifetimeMillis * refreshThreshold);
  }

  /** Whether a given token may be handed to a thread <em>right now</em>. */
  static boolean isServable(Clock clock, OAuthToken token) {
    return token != null && clock.instant().isBefore(token.expiresAt());
  }

  private String await(CompletableFuture<OAuthToken> refreshRound) {
    try {
      return refreshRound.get().accessToken();
    } catch (ExecutionException e) {
      Throwable cause = e.getCause();
      if (cause instanceof RuntimeException) {
        throw (RuntimeException) cause;
      }
      throw new ZendeskOAuthException("Failed to obtain an OAuth access token", cause);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new ZendeskOAuthException("Interrupted while awaiting an OAuth access token", e);
    }
  }
}
