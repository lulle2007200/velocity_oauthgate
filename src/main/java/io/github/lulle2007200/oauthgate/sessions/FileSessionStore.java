package io.github.lulle2007200.oauthgate.sessions;

import java.nio.file.Path;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;


import io.github.lulle2007200.oauthgate.config.ConfigStore;
import io.github.lulle2007200.oauthgate.config.SessionStore;
import io.github.lulle2007200.oauthgate.config.SessionStoreMapper;

public class FileSessionStore implements ISessionStore {
	private final Path sessionStoreFilePath;
	private SessionStore sessionStore;

	public FileSessionStore(SessionStore sessionStore, Path sessionStoreFilePath) {
		this.sessionStore = Objects.requireNonNull(sessionStore);
		this.sessionStoreFilePath = sessionStoreFilePath;
	}

	public FileSessionStore(Path sessionStoreFilePath) {
		this.sessionStoreFilePath = Objects.requireNonNull(sessionStoreFilePath);
	}

	@Override
	public synchronized CompletableFuture<Session> put(UUID uuid, Session session) {
		ensureLoaded();
		sessionStore.sessions.put(uuid, session);
		save();
		return CompletableFuture.completedFuture(session);
	}

	@Override
	public synchronized CompletableFuture<Session> get(UUID uuid) {
		ensureLoaded();
		Session session = sessionStore.sessions.get(uuid);
		if (session == null) {
			return CompletableFuture.failedFuture(new SessionNotFoundException(uuid));
		}
		return CompletableFuture.completedFuture(session);
	}

	@Override
	public synchronized CompletableFuture<Session> remove(UUID uuid) {
		ensureLoaded();
		Session session = sessionStore.sessions.remove(uuid);
		if (session == null) {
			return CompletableFuture.failedFuture(new SessionNotFoundException(uuid));
		}
		save();
		return CompletableFuture.completedFuture(session);
	}

	@Override
	public synchronized CompletableFuture<Boolean> contains(UUID uuid) {
		ensureLoaded();
		return CompletableFuture.completedFuture(sessionStore.sessions.containsKey(uuid));
	}

	private void ensureLoaded() {
		if (sessionStore != null) {
			return;
		}
		try {
			sessionStore = ConfigStore.load(sessionStoreFilePath, new SessionStoreMapper());
		} catch (RuntimeException ex) {
			throw ex;
			// throw new SessionException("Failed to load sessions from file", ex);
		}
	}

	private void save() {
		ensureLoaded();
		try {
			ConfigStore.save(sessionStoreFilePath, sessionStore, new SessionStoreMapper());
		} catch (RuntimeException ex) {
			throw new SessionException("Failed to save sessions to file", ex);
		}
	}
}
