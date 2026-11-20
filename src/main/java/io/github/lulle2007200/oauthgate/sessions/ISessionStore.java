package io.github.lulle2007200.oauthgate.sessions;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public interface ISessionStore {
	CompletableFuture<Session> put(UUID uuid, Session session);
	CompletableFuture<Session> get(UUID uuid);
	CompletableFuture<Session> remove(UUID uuid);
	CompletableFuture<Boolean> contains(UUID uuid);
}