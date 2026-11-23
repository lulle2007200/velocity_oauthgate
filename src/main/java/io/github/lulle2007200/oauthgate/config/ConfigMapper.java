package io.github.lulle2007200.oauthgate.config;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.google.common.net.HostAndPort;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;

import io.github.lulle2007200.oauthgate.config.dto.BypasserConfigDtoV1;
import io.github.lulle2007200.oauthgate.config.dto.ConfigDtoV1;
import io.github.lulle2007200.oauthgate.config.dto.ProviderConfigDtoV1;
import io.github.lulle2007200.oauthgate.oauth.OidcProvider;
import io.github.lulle2007200.oauthgate.sessions.SessionStoreType;

public final class ConfigMapper implements IConfigMapper<Config, ConfigDtoV1> {
	private static final VersionedFormat<ProviderConfigDtoV1> providerFormat = VersionedFormat.newBuilder(ProviderConfigDtoV1.class)
		.build();

	private static final VersionedFormat<BypasserConfigDtoV1> bypasserFormat = VersionedFormat.newBuilder(BypasserConfigDtoV1.class)
		.build();

	private static final VersionedFormat<ConfigDtoV1> format = VersionedFormat.newBuilder(ConfigDtoV1.class)
		.build();


	@Override 
	public VersionedFormat<ConfigDtoV1> getFormat() {
		return format;
	}

	@Override
	public ConfigDtoV1 getDefaultDto() {
		return ConfigDtoV1.getExample();
	}

	@Override
	public Config fromDto(ConfigDtoV1 dto) {
		if (dto.authCallbackBaseUrl == null) {
			throw new ConfigException("Auth server base url must be specified");
		}
		URI authServerBaseUrl;
		try {
			authServerBaseUrl = new URI(dto.authCallbackBaseUrl);
		} catch (URISyntaxException ex) {
			throw new ConfigException("Invalid auth server base url", ex);
		}

		InetSocketAddress bindAddress;
		try {
			HostAndPort hostAndPort;
			if (dto.bindAddress != null) {
				hostAndPort = HostAndPort.fromString(dto.bindAddress);
			} else {
				hostAndPort = HostAndPort.fromParts("0.0.0.0", 80);
			}
			bindAddress = new InetSocketAddress(hostAndPort.getHost(), hostAndPort.getPort());
		} catch (IllegalArgumentException ex) {
			throw new ConfigException("Invalid bind address", ex);
		}

		if (dto.providers == null) {
			throw new ConfigException("Providers must be specified");
		}
		List<OidcProvider> providers = new ArrayList<>();
		dto.providers.forEach((k, v) -> {
			Scope scope = new Scope();
			if (v.scopes != null) {
				for (String s : v.scopes) {
					scope.add(s);
				}
			}
			if (v.providerUrl == null) {
				throw new ConfigException("Provider URL must be specified");
			}
			Issuer issuer = new Issuer(v.providerUrl);

			if (v.clientId == null) {
				throw new ConfigException("Client ID must be specified");
			}
			ClientID clientID = new ClientID(v.clientId);

			OidcProvider provider = new OidcProvider(issuer,
		                                             clientID,
		                                             k,
		                                             scope,
		                                             Optional.ofNullable(v.rolesClaim));
			providers.add(provider);
		});
		if (providers.size() == 0) {
			throw new ConfigException("Atleast one provider must be specified");
		}

		SessionStoreType sessionStoreType = dto.sessionStoreType;
		if (sessionStoreType == null) {
			throw new ConfigException("Session store type must not be null");
		}

		Long loginTimeoutS = dto.loginTimeout;
		if (loginTimeoutS == null || loginTimeoutS < 0) {
			throw new ConfigException("Login timeout must not be null and positive");
		}
		Duration loginTimeout = Duration.ofSeconds(loginTimeoutS);

		Optional<Duration> maxSessionLifetime = Optional.ofNullable(dto.maxSessionLifetime).map(Duration::ofSeconds);
		if (maxSessionLifetime.map(duration -> !duration.isPositive()).orElse(false)) {
			throw new ConfigException("Maximum session lifetime must be positive");
		}

		Map<UUID, Set<String>> bypassers = new HashMap<>();
		if (dto.bypassers != null) {
			dto.bypassers.forEach((k, v) -> {
				Set<String> roles = Set.of();
				if (v.roles != null) {
					roles = Set.copyOf(v.roles);
				}
				bypassers.put(k, roles);
			});
		}

		return new Config(sessionStoreType,
                          loginTimeout,
                          maxSessionLifetime,
		                  authServerBaseUrl,
		                  bindAddress,
		                  providers,
		                  bypassers,
		                  Optional.ofNullable(dto.sessionFilePath));
	}

	@Override
	public ConfigDtoV1 toDto(Config config) {
		ConfigDtoV1 dto = new ConfigDtoV1();
		dto.authCallbackBaseUrl = config.authServerBaseUrl().toString();

		InetSocketAddress bindAddress = config.bindAddress();
		dto.bindAddress = HostAndPort.fromParts(bindAddress.getHostString(), bindAddress.getPort()).toString();

		Map<String, ProviderConfigDtoV1> providers = new HashMap<>();
		for(OidcProvider provider : config.providers()) {
			ProviderConfigDtoV1 providerDto = new ProviderConfigDtoV1();
			providerDto.clientId = provider.clientId().toString();
			providerDto.providerUrl = provider.issuer().toString();
			providerDto.rolesClaim = provider.rolesClaim().orElse(null);
			providerDto.scopes = provider.scope().toStringList();
			providers.put(provider.issuerFriendlyName(), providerDto);
		}
		dto.providers = providers;

		dto.sessionStoreType = config.sessionStoreType();
		dto.sessionFilePath = config.sessionFilePath().orElse(null);

		dto.loginTimeout = config.loginTimeout().toSeconds();
		
		dto.maxSessionLifetime = config.maxSessionLifetime().map(Duration::toSeconds).orElse(null);

		Map<UUID, BypasserConfigDtoV1> bypassers = new HashMap<>();
		config.bypassers().forEach((k, v) -> {
			BypasserConfigDtoV1 bypasserConfigDto = new BypasserConfigDtoV1();
			bypasserConfigDto.roles = List.copyOf(v);
			bypassers.put(k, bypasserConfigDto);
		});
		dto.bypassers = bypassers;

		return dto;
	}
}