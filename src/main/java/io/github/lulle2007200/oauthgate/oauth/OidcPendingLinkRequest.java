package io.github.lulle2007200.oauthgate.oauth;

import java.net.URI;
import java.util.concurrent.CompletableFuture;

import io.github.lulle2007200.oauthgate.sessions.Session;

public record OidcPendingLinkRequest (
	URI authUrl,
	CompletableFuture<Session> fut
) {
	public void cancel() {
		fut.cancel(true);
	}
}