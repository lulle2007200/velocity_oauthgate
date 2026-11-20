package io.github.lulle2007200.oauthgate.config.dto;

import java.util.Set;
import java.util.UUID;

public class SessionDtoV1 {
	public UUID uuid;
	public String username;
	public String subject;

	public Set<String> roles;

	public Long issuedAt;
	public Long expiresAt;

	public String refreshToken;
	public String accessToken;

	public String issuer;
	public String clientId;
}