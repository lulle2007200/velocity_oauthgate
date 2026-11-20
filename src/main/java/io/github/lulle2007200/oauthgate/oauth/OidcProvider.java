package io.github.lulle2007200.oauthgate.oauth;

import java.util.Optional;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;

public record OidcProvider (
	Issuer issuer,
	ClientID clientId,
	String issuerFriendlyName,
	Scope scope,
	Optional<String> rolesClaim
) {}