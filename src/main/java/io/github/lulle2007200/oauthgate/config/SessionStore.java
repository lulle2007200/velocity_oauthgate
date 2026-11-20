package io.github.lulle2007200.oauthgate.config;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import io.github.lulle2007200.oauthgate.sessions.Session;

public class SessionStore {
	public Map<UUID, Session> sessions = new HashMap<>();
}