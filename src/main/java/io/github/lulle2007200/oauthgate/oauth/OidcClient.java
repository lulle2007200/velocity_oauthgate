package io.github.lulle2007200.oauthgate.oauth;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.TokenRevocationRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import io.github.lulle2007200.oauthgate.util.HttpRequestSenderAdapter;

public class OidcClient {
	private final OidcDiscovery discovery;
	private final ClientID clientId;
	private final HTTPRequestSender httpRequestSender;

	private final Duration connectTimeout;
	private final Duration readTimeout;

	private final URI redirectURI;

	public OidcClient(Issuer issuer,
	                  ClientID clientId,
	                  Duration connectTimeout,
	                  Duration readTimeout,
                      HttpClient httpClient,
                      URI redirectionUri) {
		this.readTimeout = Objects.requireNonNull(readTimeout);
		this.connectTimeout = Objects.requireNonNull(connectTimeout);
		this.clientId = Objects.requireNonNull(clientId);
		this.httpRequestSender = new HttpRequestSenderAdapter(Objects.requireNonNull(httpClient));
		this.discovery = new OidcDiscovery.Builder()
			.withConnectTimeout(connectTimeout)
			.withReadTimeout(readTimeout)
			.withIssuer(Objects.requireNonNull(issuer))
			.withHttpClient(httpClient)
			.build();
		this.redirectURI = Objects.requireNonNull(redirectionUri);
	}

	public CompletableFuture<Tokens> getTokens(AuthorizationCode code, CodeVerifier codeVerifier, Scope scope) {
		return discovery.getMetadata()
			.thenCompose(meta -> {
				AuthorizationCodeGrant grant = new AuthorizationCodeGrant(code, redirectURI, codeVerifier);
				HTTPRequest request = new TokenRequest(
					meta.getTokenEndpointURI(),
					clientId,
					grant,
					scope
				).toHTTPRequest();

				request.setReadTimeout((int)readTimeout.toMillis());
				request.setConnectTimeout((int)connectTimeout.toMillis());

				return CompletableFuture.supplyAsync(() -> {
					try {
						return request.send(httpRequestSender);
					} catch (IOException ex) {
						throw new OidcException(ex);
					}
				}).thenApply(res -> {
					TokenResponse tokenResponse;
					try {
						tokenResponse = TokenResponse.parse(res);
					} catch (ParseException ex) {
						throw new OidcException("Invalid code exchange response", ex);
					}

					if (!tokenResponse.indicatesSuccess()) {
						ErrorObject error = tokenResponse.toErrorResponse().getErrorObject();
						throw new OidcException(error);
					}

					return tokenResponse.toSuccessResponse().getTokens();
				});
			});
		}

	public CompletableFuture<UserInfo> getUserInfo(AccessToken accessToken) {
		return discovery.getMetadata().thenCompose(meta -> {
			HTTPRequest request = new UserInfoRequest(
				meta.getUserInfoEndpointURI(),
				accessToken
			).toHTTPRequest();

			request.setReadTimeout((int) readTimeout.toMillis());
			request.setConnectTimeout((int) connectTimeout.toMillis());

			return CompletableFuture.supplyAsync(() -> {
				try {
					return request.send(httpRequestSender);
				} catch (IOException ex) {
					throw new OidcException(ex);
				}
			});
		}).thenApply(res -> {
			UserInfoResponse userInfoResponse;
			try {
				userInfoResponse = UserInfoResponse.parse(res);
			} catch (ParseException ex) {
				throw new OidcException("Invalid userinfo response", ex);
			}

			if (!userInfoResponse.indicatesSuccess()) {
				ErrorObject error = userInfoResponse.toErrorResponse().getErrorObject();
				throw new OidcException(error);
			}

			return userInfoResponse.toSuccessResponse().getUserInfo();
		});
	}

	public CompletableFuture<Tokens> refreshTokens(RefreshToken refreshToken, Scope scope) {
		return discovery.getMetadata().thenCompose(meta -> {
			RefreshTokenGrant refreshTokenGrant = new RefreshTokenGrant(refreshToken);

			HTTPRequest request = new TokenRequest(
				meta.getTokenEndpointURI(),
				clientId,
				refreshTokenGrant,
				scope
			).toHTTPRequest();

			request.setReadTimeout((int) readTimeout.toMillis());
			request.setConnectTimeout((int) connectTimeout.toMillis());

			return CompletableFuture.supplyAsync(() -> {
				try {
					return request.send(httpRequestSender);
				} catch (IOException ex) {
					throw new CompletionException(ex);
				}
			}).thenApply(res -> {
				TokenResponse tokenResponse;
				try {
					tokenResponse = TokenResponse.parse(res);
				} catch (ParseException ex) {
					throw new OidcException("Invalid token response", ex);
				}

				if (!tokenResponse.indicatesSuccess()) {
					ErrorObject error = tokenResponse.toErrorResponse().getErrorObject();
					throw new OidcException(error);
				}

				return tokenResponse.toSuccessResponse().getTokens();	
			});
		});
	}

	public CompletableFuture<Void> revokeToken(Token token) {
		return discovery.getMetadata().thenCompose(meta -> {
			HTTPRequest request = new TokenRevocationRequest(
				meta.getRevocationEndpointURI(),
				clientId,
				token
			).toHTTPRequest();

			request.setReadTimeout((int) readTimeout.toMillis());
			request.setConnectTimeout((int) connectTimeout.toMillis());

			return CompletableFuture.supplyAsync(() -> {
				try {
					return request.send(httpRequestSender);
				} catch (IOException ex) {
					throw new OidcException("Invalid token introspection response", ex);
				}
			});
		}).thenApply(res -> {
			if (res.getStatusCode() != 200) {
				ErrorObject error = ErrorObject.parse(res);
				throw new OidcException("Failed to revoke token: " + error.getCode() + " " + error.getDescription());
			}
			return null;
		});
	}

	public CompletableFuture<TokenIntrospectionSuccessResponse> introspectToken(Token token) {
		Objects.requireNonNull(token, "token must not be null");
		return discovery.getMetadata().thenCompose(meta -> {
			HTTPRequest request = new TokenIntrospectionRequest(meta.getIntrospectionEndpointURI(), token)
				.toHTTPRequest();

			request.setConnectTimeout((int)connectTimeout.toMillis());
			request.setReadTimeout((int)readTimeout.toMillis());

			return CompletableFuture.supplyAsync(() -> {
				try {
					return request.send(httpRequestSender);
				} catch (IOException ex) {
					throw new OidcException(ex);
				}
			}).thenApply(res -> {
				TokenIntrospectionResponse introspectionResponse;
				try {
					introspectionResponse = TokenIntrospectionResponse.parse(res);
				} catch (ParseException ex) {
					throw new OidcException(ex);
				}
				if (!introspectionResponse.indicatesSuccess()) {
					ErrorObject error = introspectionResponse.toErrorResponse().getErrorObject();
					throw new OidcException(error);
				}

				return introspectionResponse.toSuccessResponse();
			});
		});
	}
}
