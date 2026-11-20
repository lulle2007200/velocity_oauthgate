package io.github.lulle2007200.oauthgate;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;

import org.slf4j.Logger;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.PreTransferEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;

import io.github.lulle2007200.oauthgate.luckperms.ILuckPermsIntegration;
import io.github.lulle2007200.oauthgate.oauth.OidcAuthService;
import io.github.lulle2007200.oauthgate.oauth.OidcAuthState;
import io.github.lulle2007200.oauthgate.oauth.OidcException;
import io.github.lulle2007200.oauthgate.oauth.OidcPendingLinkRequest;
import io.github.lulle2007200.oauthgate.sessions.Session;

public abstract class OauthGate implements IOauthGate {
	sealed interface AuthResult permits LinkRequired, RefreshLoginRequired, AuthError, AutoRefreshError, Allowed {}

	record LinkRequired(URI url, CompletableFuture<Session> fut) implements AuthResult {}
	record RefreshLoginRequired(URI url, CompletableFuture<Session> fut) implements AuthResult {}
	record AutoRefreshError(String message) implements  AuthResult {}
	record AuthError(String message) implements AuthResult {}
	record Allowed() implements AuthResult {}

	private record RefreshTask(
		CompletableFuture<Void> timer, 
		CompletableFuture<Void> done
	) {}

	private final OidcAuthService authService;
	private final ILuckPermsIntegration luckPerms;
	private final Optional<Duration> maxSessionLifetime;
	private final Map<UUID, RefreshTask> refreshTasks = new ConcurrentHashMap<>();
	protected final Logger logger;
	protected final ProxyServer proxy;

	public OauthGate(OidcAuthService authService, 
	                 ILuckPermsIntegration luckPerms, 
	                 Optional<Duration> maxSessionLifetime, 
	                 ProxyServer proxy,
	                 Logger logger) {
		this.authService = Objects.requireNonNull(authService);
		this.logger = Objects.requireNonNull(logger);
		this.luckPerms = Objects.requireNonNull(luckPerms);
		this.maxSessionLifetime = Objects.requireNonNull(maxSessionLifetime);
		this.proxy = Objects.requireNonNull(proxy);
	}

	@Override
	public void onLogin(LoginEvent event) {}

	@Override
	public void onPreTransfer(PreTransferEvent event) {}

	@Override
	public void onLogout(DisconnectEvent event) {}

	protected void refreshLogin(Player player, BiConsumer<Player, AuthResult> resultHandler) {
		UUID uuid = player.getUniqueId();
		Set<String> oldRoles = authService.getRoles(uuid).join();
		String username = player.getUsername();
		OidcPendingLinkRequest request = authService.refreshLogin(uuid, username).join();
		CompletableFuture<Session> fut = request.fut().thenApply(session -> {
			Set<String> newRoles = session.roles();
			Optional<Instant> expiresAt = getExpiresAt(session.expiresAt());
			updateLuckPermsRoles(uuid, oldRoles, newRoles, expiresAt, true);
			if (player.isActive()) {
				scheduleRefresh(player, expiresAt, resultHandler);
			}
			return session;
		})
		.exceptionally(ex -> {
			request.cancel();
			updateLuckPermsRoles(uuid, oldRoles, Set.of(), null, true);
			throw ex instanceof CompletionException ce ?  ce : new CompletionException(ex);
		});
		resultHandler.accept(player, new RefreshLoginRequired(request.authUrl(), fut));
	}

	protected void link(Player player, BiConsumer<Player, AuthResult> resultHandler) {
		UUID uuid = player.getUniqueId();
		Set<String> oldRoles = authService.getRoles(uuid).join();
		String username = player.getUsername();

		OidcPendingLinkRequest request = authService.link(uuid, username);
		CompletableFuture<Session> fut = request.fut().thenApply(session -> {
			Set<String> newRoles = session.roles();
			Optional<Instant> expiresAt = getExpiresAt(session.expiresAt());
			updateLuckPermsRoles(uuid, oldRoles, newRoles, expiresAt, true);
			if (player.isActive()) {
				scheduleRefresh(player, expiresAt, resultHandler);
			}
			return session;
		})
		.exceptionally(ex -> {
			request.cancel();
			updateLuckPermsRoles(uuid, oldRoles, Set.of(), null, true);
			throw ex instanceof CompletionException ce ?  ce : new CompletionException(ex);
		});
		resultHandler.accept(player, new LinkRequired(request.authUrl(), fut));
	}

	protected void refreshSession(Player player, BiConsumer<Player, AuthResult> resultHandler) {
		UUID uuid = player.getUniqueId();
		String username = player.getUsername();
		authService.getRoles(uuid)
			.thenCompose(oldRoles -> {
				return authService.refreshSession(uuid, username)
					.thenAccept(session -> {
						Optional<Instant> expiresAt = getExpiresAt(session.expiresAt());
						updateLuckPermsRoles(uuid, oldRoles, session.roles(), expiresAt, true);
						if (player.isActive()) {
							scheduleRefresh(player, expiresAt, resultHandler);
						}
					})
					.exceptionally(ex -> {
						updateLuckPermsRoles(uuid, oldRoles, Set.of(), null, true);
						throw ex instanceof CompletionException ce ?  ce : new CompletionException(ex);
					});
			}).join();
	}

	protected void authentiacated(Player player, BiConsumer<Player, AuthResult> resultHandler, Optional<Instant> expiresAt) {
		Optional<Instant> expiresAt1 = getExpiresAt(expiresAt);
		if (player.isActive()) {
			scheduleRefresh(player, expiresAt1, resultHandler);
		}
		resultHandler.accept(player, new Allowed());
	}

	protected void authError(Player player, String message, BiConsumer<Player, AuthResult> resultHandler) {
		resultHandler.accept(player, new AuthError(message));
	}

	protected void authenticate(Player player,
                                BiConsumer<Player, AuthResult> resultHandler) {
		UUID uuid = player.getUniqueId();
		String username = player.getUsername();
		try {
			OidcAuthState state = authService.getAuthState(uuid).join();

			if (state instanceof OidcAuthState.Allowed allowed) {
				authentiacated(player, resultHandler, allowed.expiresAt());
				return;
			}else if (state instanceof OidcAuthState.Expired) {
				try {
					refreshSession(player, resultHandler);
				} catch (RuntimeException ex) {
					if (ex.getCause() instanceof OidcException oidcEx) {
						if (OAuth2Error.INVALID_GRANT_CODE.equals(oidcEx.getCode())) {
							refreshLogin(player, resultHandler);
							return;
						}
					} 
					throw ex;
				}
			} else {
				link(player, resultHandler);
			}
		} catch (Exception ex) {
			logger.error("Auth failed for {} ({}): {}", username, uuid, ex.getMessage());
			authError(player, ex.getMessage(), resultHandler);
		}
	}

	protected void scheduleRefresh(Player player, Optional<Instant> expiresAt, BiConsumer<Player, AuthResult> resultHandler) {
		if (expiresAt.isEmpty()) {
			return;
		}

		UUID uuid = player.getUniqueId();

		Duration refreshIn = Duration.between(Instant.now(), expiresAt.get());
		if (refreshIn.isNegative()) {
			refreshIn = Duration.ZERO;
		}

		// TODO: configurable margins
		Duration margin = refreshIn.dividedBy(10);
		if (margin.compareTo(Duration.ofSeconds(60)) > 0) {
			margin = Duration.ofSeconds(60);
		}

		long refreshInS = Math.max(0, refreshIn.minus(margin).toSeconds());

		CompletableFuture<Void> timer = new CompletableFuture<Void>()
			.completeOnTimeout(null, refreshInS, TimeUnit.SECONDS);

		CompletableFuture<Void> ready = new CompletableFuture<>();

		AtomicReference<RefreshTask> self = new AtomicReference<>();

		CompletableFuture<Void> done = timer
			.thenCompose(v -> ready)
			.thenRunAsync(() -> {
				refreshSession(player, resultHandler);
			})
			.exceptionally(ex -> {
				if (!(ex.getCause() instanceof CancellationException)) {
					resultHandler.accept(player, new AutoRefreshError(ex.getMessage()));
				}
				return null;
			})
			.whenComplete((_, _) -> {
				refreshTasks.remove(uuid, self.get());
			});

		RefreshTask task = new RefreshTask(timer, done);
		self.set(task);
		RefreshTask old = refreshTasks.put(uuid, task);

		if (old != null) {
			old.timer().cancel(false);
			old.done().whenComplete((r, t) -> ready.complete(null));
		} else {
			ready.complete(null);
		}
	}

	private Optional<Instant> getExpiresAt(Optional<Instant> expiresAt) {
		Optional<Instant> maxExpiresAt = maxSessionLifetime.map(lifetime -> Instant.now().plus(lifetime));
		if (expiresAt.isPresent()) {
			if (maxExpiresAt.isPresent()) {
				if (expiresAt.get().isBefore(maxExpiresAt.get())) {
					return Optional.of(expiresAt.get());
				} else {
					return Optional.of(maxExpiresAt.get());
				}
			}
			return Optional.of(expiresAt.get());
		}
		return Optional.of(maxExpiresAt.get());
	}

	private void updateLuckPermsRoles(UUID uuid, Set<String> oldRoles, Set<String> newRoles, Optional<Instant> expiresAt, boolean linked) {
		luckPerms.updateUser(uuid, user -> {
			user.removeRoles(oldRoles);
			user.addRoles(newRoles, expiresAt);
			user.setLinked(linked);
		});
	}
}
