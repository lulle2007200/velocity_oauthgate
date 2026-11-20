package io.github.lulle2007200.oauthgate.sessions;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class MemorySessionStore implements ISessionStore {
	private final Map<UUID, Session> sessions = new HashMap<>();

	@Override
	public CompletableFuture<Session> put(UUID uuid, Session session) {
		sessions.put(uuid, session);
		return CompletableFuture.completedFuture(session);
	}

	@Override
	public CompletableFuture<Session> get(UUID uuid) {
		Session session = sessions.get(uuid);
		if (session == null) {
			return CompletableFuture.failedFuture(new SessionNotFoundException(uuid));
		}
		return CompletableFuture.completedFuture(session);
	}

	@Override
	public CompletableFuture<Session> remove(UUID uuid) {
		Session session = sessions.remove(uuid);
		if (session == null) {
			return CompletableFuture.failedFuture(new SessionNotFoundException(uuid));
		}
		return CompletableFuture.completedFuture(session);
	}

	@Override
	public CompletableFuture<Boolean> contains(UUID uuid) {
		boolean contains = sessions.containsKey(uuid);
		return CompletableFuture.completedFuture(contains);
	}}