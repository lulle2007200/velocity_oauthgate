package io.github.lulle2007200.oauthgate.sessions;

import java.util.UUID;

public class SessionNotFoundException extends SessionException {
	public SessionNotFoundException(UUID uuid) {
		super("No session for " + uuid);
	}
}