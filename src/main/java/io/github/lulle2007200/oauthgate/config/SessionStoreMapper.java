package io.github.lulle2007200.oauthgate.config;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

import io.github.lulle2007200.oauthgate.config.dto.SessionDtoV1;
import io.github.lulle2007200.oauthgate.config.dto.SessionStoreDtoV1;
import io.github.lulle2007200.oauthgate.oauth.OidcProviderId;
import io.github.lulle2007200.oauthgate.sessions.Session;

public final class SessionStoreMapper implements IConfigMapper<SessionStore, SessionStoreDtoV1> {
	private static final VersionedFormat<SessionDtoV1> sessionFormat = VersionedFormat.newBuilder(SessionDtoV1.class)
		.build();

	private static final VersionedFormat<SessionStoreDtoV1> format = VersionedFormat.newBuilder(SessionStoreDtoV1.class)
		.build();


	@Override 
	public VersionedFormat<SessionStoreDtoV1> getFormat() {
		return format;
	}

	@Override
	public SessionStoreDtoV1 getDefaultDto() {
		return new SessionStoreDtoV1();
	}

	@Override
	public SessionStore fromDto(SessionStoreDtoV1 dto) {
		SessionStore store = new SessionStore();

		if (dto.sessions == null) {
			throw new ConfigException("Sessions must be specified");
		}
		for (SessionDtoV1 session : dto.sessions) {
			if (session.clientId == null || session.issuer == null) {
				throw new ConfigException("Issuer and client ID must be specified");
			}
			OidcProviderId providerId = new OidcProviderId(new Issuer(session.issuer), 
			                                               new ClientID(session.clientId));

			if (session.uuid == null     ||
		        session.username == null ||
		        session.subject == null  ||
		        session.issuedAt == null ||
		        session.accessToken == null) {
				throw new ConfigException("UUID, username, subject, issuedAt and accessToken must be specified");
			}

			UUID uuid = session.uuid;
			String username = session.username;
			Subject subject = new Subject(session.subject);
			Set<String> roles;
			if (session.roles == null) {
				roles = Set.of();
			} else {
				roles = session.roles;
			}
			Instant issuedAt = Instant.ofEpochSecond(session.issuedAt);
			Optional<Instant> expiresAt = Optional.ofNullable(session.expiresAt).map(Instant::ofEpochSecond);
			Optional<RefreshToken> refreshToken = Optional.ofNullable(session.refreshToken).map(RefreshToken::new);
			AccessToken accessToken = new BearerAccessToken(session.accessToken);

			store.sessions.put(uuid, new Session(uuid, 
			                                     username, 
			                                     subject, 
			                                     roles, 
			                                     issuedAt, 
			                                     expiresAt, 
			                                     refreshToken, 
			                                     accessToken, 
			                                     providerId));
		}

		return store;
	}

	@Override
	public SessionStoreDtoV1 toDto(SessionStore store) {
		SessionStoreDtoV1 dto = new SessionStoreDtoV1();

		ArrayList<SessionDtoV1> sessions = new ArrayList<>(store.sessions.size());

		store.sessions.forEach((uuid, session) -> {
			SessionDtoV1 sessionDto = new SessionDtoV1();
			sessionDto.uuid = uuid;
			sessionDto.username = session.username();
			sessionDto.subject = session.subject().toString();
			sessionDto.roles = session.roles();
			sessionDto.issuedAt = session.issuedAt().getEpochSecond();
			sessionDto.expiresAt = session.expiresAt().map(Instant::getEpochSecond).orElse(null);
			sessionDto.refreshToken = session.refreshToken().map(RefreshToken::toString).orElse(null);
			sessionDto.accessToken = session.accessToken().toString();
			sessionDto.issuer = session.providerId().issuer().toString();
			sessionDto.clientId = session.providerId().clientID().toString();
			sessions.add(sessionDto);
		});

		dto.sessions = sessions;

		return dto;
	}
}