package io.github.lulle2007200.oauthgate.oauth;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;

public record OidcProviderId (
	Issuer issuer,
	ClientID clientID
) {
	public static final OidcProviderId NULL = new OidcProviderId(null, null);
}