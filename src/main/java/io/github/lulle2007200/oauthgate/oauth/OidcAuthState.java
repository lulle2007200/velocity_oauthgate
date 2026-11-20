package io.github.lulle2007200.oauthgate.oauth;

import java.time.Instant;
import java.util.Optional;

public sealed interface OidcAuthState permits OidcAuthState.Allowed, OidcAuthState.NotLinked, OidcAuthState.Expired {
	record Allowed(Optional<Instant> expiresAt) implements OidcAuthState {}
    record NotLinked() implements OidcAuthState {}
    record Expired() implements OidcAuthState {}

    public static OidcAuthState allowed(Optional<Instant> expiresAt) {
    	return new Allowed(expiresAt);
    }

    public static OidcAuthState notLinked() {
    	return new NotLinked();
    }

    public static OidcAuthState expired() {
    	return new Expired();
    }
}
