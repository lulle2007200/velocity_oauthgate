package io.github.lulle2007200.oauthgate;

import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;

import org.slf4j.Logger;

import com.google.inject.Inject;
import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Dependency;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;

import io.github.lulle2007200.oauthgate.config.Config;
import io.github.lulle2007200.oauthgate.config.ConfigMapper;
import io.github.lulle2007200.oauthgate.config.ConfigStore;
import io.github.lulle2007200.oauthgate.luckperms.ILuckPermsIntegration;
import io.github.lulle2007200.oauthgate.luckperms.LuckPermsIntegration;
import io.github.lulle2007200.oauthgate.luckperms.NoLuckPermsIntegration;
import io.github.lulle2007200.oauthgate.oauth.OidcAuthService;
import io.github.lulle2007200.oauthgate.oauth.OidcExchangeCodeProvider;
import io.github.lulle2007200.oauthgate.sessions.FileSessionStore;
import io.github.lulle2007200.oauthgate.sessions.ISessionStore;
import io.github.lulle2007200.oauthgate.sessions.MemorySessionStore;
import io.github.lulle2007200.oauthgate.sessions.SessionStoreType;
import net.luckperms.api.LuckPermsProvider;

@Plugin(
	id = ProjectConstants.ID,
	name = ProjectConstants.NAME,
	description = ProjectConstants.DESCRIPTION,
	version = ProjectConstants.VERSION,
	authors = { ProjectConstants.AUTHOR },
	dependencies = { @Dependency(id = "luckperms", optional = true) }
)
public final class OAuthGatePlugin {
	private final Path dataDir;
	private final ProxyServer proxyServer;
	private final Logger logger;

	private IOauthGate oauthGate;

	@Inject
	public OAuthGatePlugin(ProxyServer proxyServer, @DataDirectory Path dataDir, Logger logger) {
		this.dataDir = dataDir;
		this.proxyServer = proxyServer;
		this.logger = logger;
	}

	@Subscribe
	public EventTask onLogin(LoginEvent event) {
		if (!event.getResult().isAllowed()) {
			return null;
		}

		return EventTask.async(() -> {
			oauthGate.onLogin(event);
		});
	}

	@Subscribe
	void onInit(final ProxyInitializeEvent event) {
		init();
	}

	private Config loadConfig() {
		Path configPath = dataDir.resolve(Constants.oauthgateConfigFilename);
		return ConfigStore.load(configPath, new ConfigMapper());
	}

	private void init() {
		Duration connectTimeout = Duration.ofSeconds(10);
		Duration readTimeout = Duration.ofSeconds(10);

		Config config = loadConfig();

		ILuckPermsIntegration luckPerms;
		if (proxyServer.getPluginManager().isLoaded("luckperms")) {
			luckPerms = new LuckPermsIntegration(LuckPermsProvider.get());
		} else {
			luckPerms = new NoLuckPermsIntegration();
		}

		HttpClient httpClient = HttpClient.newBuilder()
			.connectTimeout(connectTimeout)
			.build();

		ISessionStore sessionStore;
		switch (config.sessionStoreType()) {
			case SessionStoreType.memory:
				sessionStore = new MemorySessionStore();
				break;
			case SessionStoreType.file:
				Path sessionStoreFilePath = dataDir.resolve(Constants.oauthgateSessionStoreFilename);
				sessionStore = new FileSessionStore(sessionStoreFilePath);
				break;
			default:
				throw new AssertionError();
		}

		OidcExchangeCodeProvider exchangeCodeProvider = new OidcExchangeCodeProvider(config.authServerBaseUrl(), 
		                                                                             config.loginTimeout(), 
		                                                                             httpClient, 
		                                                                             readTimeout, 
		                                                                             connectTimeout);

		OidcAuthService authService = OidcAuthService.newBuilder()
			.withConnectTimeout(connectTimeout)
			.withReadTimeout(readTimeout)
			.withHttpClient(httpClient)
			.withExchangeCodeProvider(exchangeCodeProvider)
			.withSessionStore(sessionStore)
			.withProviders(Set.copyOf(config.providers()))
			.withBypassers(config.bypassers())
			.build();

		this.oauthGate = new KickOauthGate(authService, 
		                                   luckPerms, 
		                                   config.maxSessionLifetime(),
		                                   proxyServer,
		                                   logger);
	}
}