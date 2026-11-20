package io.github.lulle2007200.oauthgate.oauth;

import com.nimbusds.oauth2.sdk.AuthorizationCode;

public record OidcExchangeCodeRequestResult (
	AuthorizationCode exchangeCode,
	OidcProviderId provider
) {}