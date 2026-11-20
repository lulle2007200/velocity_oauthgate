package io.github.lulle2007200.oauthgate.config;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import io.github.lulle2007200.oauthgate.oauth.OidcProvider;
import io.github.lulle2007200.oauthgate.sessions.SessionStoreType;

public record Config (
	SessionStoreType sessionStoreType,
	Duration loginTimeout,
	Optional<Duration> maxSessionLifetime,
	URI authServerBaseUrl,
	List<OidcProvider> providers,
	Map<UUID, Set<String>> bypassers,
	Optional<String> sessionFilePath
) {}