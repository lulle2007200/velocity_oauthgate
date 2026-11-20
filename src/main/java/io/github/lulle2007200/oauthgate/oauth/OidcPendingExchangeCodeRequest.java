package io.github.lulle2007200.oauthgate.oauth;

import java.net.URI;
import java.util.concurrent.CompletableFuture;

public record OidcPendingExchangeCodeRequest (
	URI authUrl,
	CompletableFuture<OidcExchangeCodeRequestResult> result,
	Runnable cancelAction
) {
	public OidcPendingExchangeCodeRequest(URI authUrl, CompletableFuture<OidcExchangeCodeRequestResult> result) {
		this(authUrl, result, () -> {});
	}

	public void cancel() {
		cancelAction.run();
	}
}