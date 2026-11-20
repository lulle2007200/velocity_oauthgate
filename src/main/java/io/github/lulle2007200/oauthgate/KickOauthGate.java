package io.github.lulle2007200.oauthgate;

import java.net.URI;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import org.slf4j.Logger;

import com.velocitypowered.api.event.ResultedEvent;
import com.velocitypowered.api.event.ResultedEvent.ComponentResult;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.PreTransferEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;

import io.github.lulle2007200.oauthgate.luckperms.ILuckPermsIntegration;
import io.github.lulle2007200.oauthgate.oauth.OidcAuthService;
import io.github.lulle2007200.oauthgate.sessions.Session;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.TextColor;
import net.kyori.adventure.text.format.TextDecoration;

public class KickOauthGate extends OauthGate {
	public KickOauthGate(OidcAuthService authService, 
	                     ILuckPermsIntegration luckPerms, 
	                     Optional<Duration> maxSessionLifetime,
	                     ProxyServer proxy,
	                     Logger logger) {
		super(authService, luckPerms, maxSessionLifetime, proxy, logger);
	}

	@Override
	public void onLogin(LoginEvent event) {
		Player player = event.getPlayer();
		authenticate(player, (Player player1, AuthResult result) -> {
			this.handleAuthResult(player1, result, event);
		});
	}

	@Override
	public void onPreTransfer(PreTransferEvent event) {}

	private void handleAuthResult(Player player, AuthResult result, ResultedEvent<?> event) {
		switch (result) {
			case LinkRequired r -> {
				handleLinkRequired(player, r.url(), event);
			}
			case RefreshLoginRequired r -> {
				handleRefreshLoginRequired(player, r.url(), r.fut(), event);
			}
			case AuthError r -> {
				handleAuthError(player, r.message(), event);
			}
			case Allowed _ -> {
				handleAllowed(player, event);
			}
			case AutoRefreshError r -> {
				handleAutoRefreshError(player, r.message());
			} 
			case null -> {}
			default -> {}
		}
	}

	private void handleAutoRefreshError(Player player, String message) {
		player = proxy.getPlayer(player.getUniqueId()).orElse(null);
		if (player != null && player.isActive()) {
			Component messageComponent = Component.text()
				.append(Component.text("Your login expired. Please rejoin"))
				.build();

			player.disconnect(messageComponent);
		}
	}

	private void handleLinkRequired(Player player,
	                                URI authUrl,
	                                ResultedEvent<?> event) {
		String url = authUrl.toString();
		Component message = Component.text()
			.append(Component.text("To link your account, Open this link in your browser:"))
			.appendNewline()
			.append(Component.text(url, TextColor.color(0x55aaff), TextDecoration.BOLD))
			.appendNewline()
			.append(Component.text("After signing in, you can rejoin the server."))
			.build();
		
		applyResult(event, ComponentResult.denied(message));
	}


	private void handleRefreshLoginRequired(Player player,
	                                        URI authUrl,
	                                        CompletableFuture<Session> fut,
	                                        ResultedEvent<?> event) {
		String url = authUrl.toString();
		Component message = Component.text()
			.append(Component.text("Your login expired. Open this link in your browser:"))
			.appendNewline()
			.append(Component.text(url, TextColor.color(0x55aaff), TextDecoration.BOLD))
			.appendNewline()
			.append(Component.text("After signing in again, you can rejoin the server."))
			.build();

		applyResult(event, ComponentResult.denied(message));
	}

	private void handleAuthError(Player player, 
	                             String message,
	                             ResultedEvent<?> event) {
		Component messageComponent = Component.text()
			.append(Component.text("Authorization failed. Try again later."))
			.build();

		applyResult(event, ComponentResult.denied(messageComponent));
	}

	private void handleAllowed(Player player,
                               ResultedEvent<?> event) {
		applyResult(event, ComponentResult.allowed());
	}

	@SuppressWarnings("unchecked")
	private static <R extends ResultedEvent.Result> void applyResult(ResultedEvent<R> event,
                                                                     ResultedEvent.Result result) {
		event.setResult((R)result);
	}
}