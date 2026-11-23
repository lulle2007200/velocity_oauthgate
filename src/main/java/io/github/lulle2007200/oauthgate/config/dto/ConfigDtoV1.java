package io.github.lulle2007200.oauthgate.config.dto;

import java.util.Map;
import java.util.UUID;

import io.github.lulle2007200.oauthgate.sessions.SessionStoreType;

public class ConfigDtoV1 {
	// Required settings

	// Base URL to listen on for auth callbacks.
	// The callback server listens on the following urls:
	// authCallbackBaseUrl/l/[short code]
	// authCallbackBaseUrl/callback
	// authCallbackBaseUrl/auth/[short code]/[provider index]
	public String authCallbackBaseUrl;

	// OIDC providers to offer for logins.
	// Atleast one provider must be specified.
	public Map<String, ProviderConfigDtoV1> providers;

	// Optional settings

	// Address/port to listen on
	// Optional
	// Default: 0.0.0.0:80
	public String bindAddress = "0.0.0.0:80";

	// Session store type
	// Allowed values:
	// file: Sessions/account links are stored in a json file
	// memory: Use an in-memory store. Sessions/account links are not persistent
	// file: Persist sessions to a JSON file (see sessionFilePath)
	// Default: file
	public SessionStoreType sessionStoreType = SessionStoreType.file;

	// Path to the session file when sessionStoreType is "file".
	// If not set, defaults to "oauthgate-sessions.json" in the working directory.
	// Optional
	public String sessionFilePath;

	// Maximum time until a login must be completed before the login request is invalidated in seconds.
	// Default: 5min
	public Long loginTimeout = Long.valueOf(300);

	// Maximum session lifetime in seconds.
	// After a maximum of maxSessionLifeTime, players will be re-authenticated and roles updated.
	// May be set to null.
	// If null, and a players token has no expiration time, no automatic re-authentication will be performed and
	// players are only authenticated at login.
	// Default: 12h
	public Long maxSessionLifetime = Long.valueOf(43200);

	// Players that may bypass authentication.
	public Map<UUID, BypasserConfigDtoV1> bypassers = Map.of();

	public static ConfigDtoV1 getExample() {
		ConfigDtoV1 dto = new ConfigDtoV1();
		dto.authCallbackBaseUrl = "http://auth.minecraft.example.com";
		dto.providers = Map.of("Example Provider",
                               ProviderConfigDtoV1.getExample());
		dto.bypassers = Map.of(UUID.fromString("3f2b8c1e-5a4d-4c0e-9b7a-1d2e3f4a5b6c"),
		                       BypasserConfigDtoV1.getExample());
		return dto;
	}
}