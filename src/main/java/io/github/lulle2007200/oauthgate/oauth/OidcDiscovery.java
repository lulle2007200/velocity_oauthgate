package io.github.lulle2007200.oauthgate.oauth;

import java.io.IOException;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import io.github.lulle2007200.oauthgate.util.HttpRequestSenderAdapter;

public class OidcDiscovery {
	public static class Builder {
		private Duration readTimeout = Duration.ZERO;
		private Duration connectTimeout = Duration.ZERO;
		private Duration ttl = Duration.ofHours(24);
		private HttpClient httpClient;
		private Issuer issuer;

		public Builder withHttpClient(HttpClient httpClient) {
			this.httpClient = httpClient;
			return this;
		}

		public Builder withReadTimeout(Duration readTimeout) {
			if (readTimeout != null && (readTimeout.isNegative() || readTimeout.isZero())) {
				throw new IllegalArgumentException("Read timeout must be positive");
			}
			this.readTimeout = readTimeout;
			return this;
		}

		public Builder withConnectTimeout(Duration connectTimeout) {
			if (connectTimeout != null && (connectTimeout.isNegative() || connectTimeout.isZero())) {
				throw new IllegalArgumentException("Connect timeout must be positive");
			}
			this.connectTimeout = connectTimeout;
			return this;
		}

		public Builder withIssuer(Issuer issuer) {
			this.issuer = issuer;
			return this;
		}

		public Builder withTtl(Duration ttl) {
			if (ttl != null && (ttl.isNegative() || ttl.isZero())) {
				throw new IllegalArgumentException("Ttl must be positive");
			}
			this.ttl = ttl;
			return this;
		}

		public OidcDiscovery build() {
			if (httpClient == null) {
				throw new IllegalArgumentException("Http client not set");
			}

			if (issuer == null) {
				throw new IllegalArgumentException("Issuer url not set");
			}

			return new OidcDiscovery(httpClient,
		                             readTimeout,
		                             connectTimeout,
		                             issuer,
		                             ttl);
		}
	}

	private final HTTPRequestSender httpRequestSender;
	private final Issuer issuer;
	private final Duration ttl;
	private final Duration readTimeout;
	private final Duration connectTimeout;

	private OIDCProviderMetadata value;
	private CompletableFuture<OIDCProviderMetadata> fut;
	private Instant expiresAt;

	public OidcDiscovery(HttpClient httpClient,
	                     Duration readTimeout,
	                     Duration connectTimeout,
	                 	 Issuer issuer,
	                 	 Duration ttl) {
		this.httpRequestSender = new HttpRequestSenderAdapter(Objects.requireNonNull(httpClient));
		this.ttl = Objects.requireNonNull(ttl);
		this.issuer = Objects.requireNonNull(issuer);
		this.readTimeout = Objects.requireNonNull(readTimeout);
		this.connectTimeout = Objects.requireNonNull(connectTimeout);
	}

	public static Builder newBuilder() {
		return new Builder();
	}

	public synchronized CompletableFuture<OIDCProviderMetadata> getMetadata() {
		if (value != null && expiresAt != null && expiresAt.isAfter(Instant.now())) {
			return CompletableFuture.completedFuture(value);
		}

		if (fut == null) {
			fut = fetch()
				.whenComplete((res, ex) -> {
					synchronized (this) {
						fut = null;
						if (ex  != null) {
							value = null;
						} else {
							value = res;
							expiresAt = Instant.now().plus(ttl);
						}
					}
				});
		}

		return fut;
	}

	private CompletableFuture<OIDCProviderMetadata> fetch() {
		HTTPRequest request = new OIDCProviderConfigurationRequest(issuer).toHTTPRequest();

		request.setReadTimeout((int)readTimeout.toMillis());
		request.setConnectTimeout((int)connectTimeout.toMillis());

		return CompletableFuture.supplyAsync(() -> {
			try {
				return request.send(httpRequestSender);
			} catch (IOException ex) {
				throw new OidcException(ex);
			}
		}).thenApply(res -> {
			if (res.getStatusCode() != 200) {
				ErrorObject error = ErrorObject.parse(res);
				throw new OidcException("Failed to get metadata: " + error.getCode() + " " + error.getDescription());
			}
			OIDCProviderMetadata meta;
			try {
				meta = OIDCProviderMetadata.parse(res.getBody());
			} catch (ParseException ex) {
				throw new OidcException("Invalid OIDC metadata", ex);
			}
			if (!issuer.equals(meta.getIssuer())) {
				throw new OidcException("Issuer mismatch");
			}
			return meta;
		});
	}
}
