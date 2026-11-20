package io.github.lulle2007200.oauthgate.oauth;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;

public interface IOidcExchangeCodeProvider {
	OidcPendingExchangeCodeRequest getExchangeCode(String username, 
	                                               UUID uuid, 
	                                               CodeChallenge codeChallenge, 
	                                               CodeChallengeMethod method, 
	                                               List<OidcProvider> providers);

	URI getCallbackUrl();
}