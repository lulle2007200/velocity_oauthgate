package io.github.lulle2007200.oauthgate.oauth;

import java.net.http.HttpClient;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.concurrent.CompletionException;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import io.github.lulle2007200.oauthgate.sessions.ISessionStore;
import io.github.lulle2007200.oauthgate.sessions.Session;
import io.github.lulle2007200.oauthgate.sessions.SessionNotFoundException;

public class OidcAuthService {
	public static class Builder {
		private Map<OidcProviderId, OidcProvider> providers = new HashMap<>();
		private ISessionStore sessionStore;
		private HttpClient httpClient;
		private Duration connectTimeout = Duration.ZERO;
		private Duration readTimeout = Duration.ZERO;
		private IOidcExchangeCodeProvider exchangeCodeProvider;
		private Map<UUID, Set<String>> bypassers = new HashMap<>();

		public Builder withProviders(Set<OidcProvider> providers) {
			Objects.requireNonNull(providers);
			for (OidcProvider provider : providers) {
				withProvider(provider);
			}
			return this;
		}

		public Builder withProvider(OidcProvider provider) {
			provider = Objects.requireNonNull(provider);
			providers.put(new OidcProviderId(provider.issuer(), provider.clientId()),
		                  provider);
			return this;
		}

		public Builder withSessionStore(ISessionStore sessionStore) {
			this.sessionStore = Objects.requireNonNull(sessionStore);
			return this;
		}

		public Builder withHttpClient(HttpClient httpClient) {
			this.httpClient = Objects.requireNonNull(httpClient);
			return this;
		}

		public Builder withConnectTimeout(Duration connectTimeout) {
			this.connectTimeout = validateDuration(connectTimeout);
			return this;
		}

		public Builder withReadTimeout(Duration readTimeout) {
			this.readTimeout = validateDuration(readTimeout);
			return this;
		}

		public Builder withExchangeCodeProvider(IOidcExchangeCodeProvider exchangeCodeProvider) {
			this.exchangeCodeProvider = Objects.requireNonNull(exchangeCodeProvider);
			return this;
		}

		public Builder withBypasser(UUID uuid, Set<String> roles) {
			bypassers.put(uuid, Set.copyOf(roles));
			return this;
		}

		public Builder withBypassers(Map<UUID, Set<String>> bypassers) {
			Objects.requireNonNull(bypassers);
			bypassers.forEach((k, v) -> {
				withBypasser(k, v);
			});
			return this;
		}

		public OidcAuthService build() {
			return new OidcAuthService(providers,
			                           bypassers,
			                           sessionStore, 
			                           connectTimeout, 
			                           readTimeout, 
			                           exchangeCodeProvider, 
			                           httpClient);
		}

		private Duration validateDuration(Duration duration) {
			duration = Objects.requireNonNull(duration);
			if (duration.isNegative()) {
				throw new IllegalArgumentException("Duration must be positive");
			}
			return duration;
		}
	}

	public static Builder newBuilder() {
		return new Builder();
	}

	private final Map<OidcProviderId, OidcProvider> providers;
	private final ISessionStore sessionStore;
	private final Map<OidcProviderId, OidcClient> clients = new HashMap<>();
	private final IOidcExchangeCodeProvider exchangeCodeProvider;
	private final Map<UUID, Set<String>> bypassers;

	private final Map<UUID, CompletableFuture<Void>> refreshTasks = new HashMap<>();
	private final Map<UUID, OidcPendingLinkRequest> pendingLoginRequests = new Hashtable<>();

	public OidcAuthService(Map<OidcProviderId, OidcProvider> providers,
	                       Map<UUID, Set<String>> bypassers,
                           ISessionStore sessionStore,
                           Duration connectTimeout,
                           Duration readTimeout,
                           IOidcExchangeCodeProvider exchangeCodeProvider,
                           HttpClient httpClient) {
		this.providers = Objects.requireNonNull(providers);
		this.sessionStore = Objects.requireNonNull(sessionStore);
		this.exchangeCodeProvider = Objects.requireNonNull(exchangeCodeProvider);
		this.bypassers = Objects.requireNonNull(bypassers);

		providers.forEach((k, v) -> {
			clients.put(k,
		                new OidcClient(v.issuer(), 
		                               v.clientId(), 
		                               Objects.requireNonNull(connectTimeout), 
		                               Objects.requireNonNull(readTimeout), 
		                               Objects.requireNonNull(httpClient),
		                               exchangeCodeProvider.getCallbackUrl()));
		});
	}

	private OidcClient getClient(OidcProviderId provider) {
		return Objects.requireNonNull(clients.get(provider));
	}

	private OidcClient getClient(Session session) {
		return getClient(session.providerId());
	}

	private OidcProvider getProvider(OidcProviderId providerId) {
		return providers.get(providerId);
	}

	private CompletableFuture<Session> createSession(UUID uuid,
	                                                 String username, 
	                                                 AccessToken accessToken, 
	                                                 RefreshToken refreshToken,
	                                                 OidcProviderId providerId,
	                                                 Instant issuedAt) {
		OidcClient client = getClient(providerId);
		OidcProvider provider = getProvider(providerId);

		return client.getUserInfo(accessToken).thenApply(userInfo -> {
			Subject subject = userInfo.getSubject();
			Set<String> roles = Set.of();
			if (provider.rolesClaim().isPresent()) {
				List<String> rolesList = userInfo.getStringListClaim(provider.rolesClaim().get());
				if (rolesList != null) {
					roles = Set.copyOf(rolesList);
				}
			}

			Instant issueTime = issuedAt;
			Instant expirationTime = null;

			try {
				JWT jwt = JWTParser.parse(accessToken.getValue());
				JWTClaimsSet claims = jwt.getJWTClaimsSet();

				if (claims.getIssueTime() != null) {
					issueTime = claims.getIssueTime().toInstant();
				}

				if (claims.getExpirationTime() != null) {
					expirationTime = claims.getExpirationTime().toInstant();
				}

			} catch (ParseException ex) {}

			if (expirationTime == null) {
				if (accessToken.getLifetime() != 0) {
					expirationTime = issueTime.plusSeconds(accessToken.getLifetime());
				}
			}

			// TODO: Get expiration time from introspection if we still dont have it

			return new Session(uuid,
			                   username,
			                   subject,
			                   roles,
			                   issueTime,
			                   Optional.ofNullable(expirationTime),
			                   Optional.ofNullable(refreshToken),
			                   accessToken,
			                   providerId);
		});
	}

	private CompletableFuture<Session> registerSession(UUID uuid, Session session) {
		return sessionStore.put(uuid, session);
	}

	private CompletableFuture<Session> createBypassSession(UUID uuid, String username, Set<String> roles) {
		Session session = new Session(uuid,
		                              username,
		                              new Subject(),
		                              roles,
		                              Instant.now(),
		                              Optional.empty(),
		                              Optional.empty(),
		                              new BearerAccessToken(),
		                              OidcProviderId.NULL);

		return CompletableFuture.completedFuture(session);
	}

	public CompletableFuture<Session> refreshSession(UUID uuid, String username) {
		if (bypassers.containsKey(uuid)) {
			return sessionStore.contains(uuid)
				.thenCompose(contains -> {
					if (contains) {
						return sessionStore.get(uuid);
					} else {
						return CompletableFuture.completedFuture(null);
					}
				})
				.thenCompose(session -> {
					Set<String> roles = bypassers.get(uuid);
					return createBypassSession(uuid, username, roles);
				})
				.thenCompose(session -> {
					return registerSession(uuid, session);
				});
		} else {
			return sessionStore.get(uuid)
				.thenCompose(session -> {
					OidcProviderId providerId = session.providerId();
					OidcProvider provider = getProvider(providerId);
					OidcClient client = getClient(session.providerId());
					Instant issuedAt = Instant.now();

					if (session.refreshToken().isEmpty()) {
						throw new OidcException(OAuth2Error.INVALID_GRANT);
					}

					return client.refreshTokens(session.refreshToken().get(), provider.scope())
						.thenCompose(tokens -> {
							return createSession(uuid, 
							                     session.username(), 
							                     tokens.getAccessToken(), 
							                     tokens.getRefreshToken(), 
							                     session.providerId(),
							                     issuedAt);
						});
				})
				.thenCompose(session -> {
					return registerSession(uuid, session);
				});
		}
	}

	private OidcPendingLinkRequest login(UUID uuid, 
	                                     String username,
	                                     Map<OidcProviderId, OidcProvider> providers,
	                                     Consumer<Session> sessionCheck) {
		if (bypassers.containsKey(uuid)) {
			throw new OidcException("Login not supported for bypassing users");
		}

		return pendingLoginRequests.computeIfAbsent(uuid, _ -> {
			CodeChallengeMethod method = CodeChallengeMethod.S256;

			CodeVerifier codeVerifier = new CodeVerifier();
			CodeChallenge codeChallenge = CodeChallenge.compute(method, codeVerifier);

			OidcPendingExchangeCodeRequest exchangeCodeRequest = exchangeCodeProvider.getExchangeCode(username, 
			                                                                                          uuid, 
			                                                                                          codeChallenge, 
			                                                                                          method,   
			                                                                                          new ArrayList<>(providers.values()));

			CompletableFuture<Session> fut = exchangeCodeRequest.result()
				.thenCompose(res -> {
					OidcProviderId providerId = res.provider();
					OidcProvider provider = getProvider(providerId);
					OidcClient client = getClient(providerId);
					Instant issueTime = Instant.now();

					return client.getTokens(res.exchangeCode(), codeVerifier, provider.scope())
						.thenCompose(tokens -> {
							return createSession(uuid, 
							                     username, 
							                     tokens.getAccessToken(), 
							                     tokens.getRefreshToken(), 
							                     providerId,
							                     issueTime);
						});
				})
				.thenCompose(session -> {
					sessionCheck.accept(session);
					return registerSession(uuid, session);
				})
				.whenComplete((session, ex) -> {
					pendingLoginRequests.remove(uuid);
				})
				.exceptionally(ex -> {
					exchangeCodeRequest.cancel();
					throw ex instanceof CompletionException ce ?  ce : new CompletionException(ex);
				});

			return new OidcPendingLinkRequest(exchangeCodeRequest.authUrl(), fut);
		});
	}

	public OidcPendingLinkRequest link(UUID uuid, String username) {
		return login(uuid, username, providers, session -> {});
	}

	public CompletableFuture<OidcPendingLinkRequest> refreshLogin(UUID uuid, String username) {
		return sessionStore.get(uuid)
			.thenApply(session -> {
				Map<OidcProviderId, OidcProvider> providers;
				if (session.providerId().equals(OidcProviderId.NULL)) {
					providers = this.providers;
				} else {
					providers = Map.of(session.providerId(), getProvider(session.providerId()));
				}
				return login(uuid, username, providers, newSession -> {
					if (bypassers.containsKey(uuid)) {
						return;
					} else if (!newSession.providerId().equals(session.providerId())) {
						throw new OidcException("Identity provider for " + uuid + " changed");
					} else if (!newSession.subject().equals(session.subject())) {
						throw new OidcException("Subject for " + uuid + " changed");
					}
				});
			});
	}

	public CompletableFuture<OidcAuthState> getAuthState(UUID uuid) {
		return sessionStore.get(uuid)
			.thenApply(session -> {
				if (session.expiresAt().isPresent() && session.expiresAt().get().isAfter(Instant.now())) {
					return OidcAuthState.allowed(session.expiresAt());
				}
				return OidcAuthState.expired();
			})
			.exceptionally(ex -> {
				Throwable cause = ex instanceof CompletionException ce ? ce.getCause() : ex;
				// TODO: Returning expired for bypass users indicates to the caller that 
				//       it should refresh the session, which is special-cased for bypass users.
				//       Could return not linked too, but login flow returns a PendingLoginRequest with
				//       an auth url, which is not exactly necessary for bypass users.
				if (bypassers.containsKey(uuid)) {
					return OidcAuthState.expired();
				} else if (cause instanceof SessionNotFoundException) {
					return OidcAuthState.notLinked();
				}
				throw ex instanceof CompletionException ce ?  ce : new CompletionException(ex);
			});
	}

	public CompletableFuture<Set<String>> getRoles(UUID uuid) {
		return sessionStore.get(uuid)
			.thenApply(session -> {
				return session.roles();
			})
			.exceptionally(ex -> {
				if (ex.getCause() instanceof SessionNotFoundException) {
					return Set.of();
				}
				throw ex instanceof CompletionException ce ?  ce : new CompletionException(ex);
			});
	}

	public CompletableFuture<Void> unlink(UUID uuid) {
		return sessionStore.remove(uuid)
			.thenCompose(session -> {
				CompletableFuture<Void> refreshTask = refreshTasks.remove(uuid);
				if (refreshTask != null) {
					refreshTask.cancel(true);
				}
				OidcClient client = getClient(session);

				CompletableFuture<Void> revokeAccess = client.revokeToken(session.accessToken());

				if (session.refreshToken().isEmpty()) {
					return revokeAccess;
				}

				CompletableFuture<Void> revokeRefresh = client.revokeToken(session.refreshToken().get());
				return CompletableFuture.allOf(revokeRefresh, revokeAccess);
			});
	}
}
