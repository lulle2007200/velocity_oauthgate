package io.github.lulle2007200.oauthgate.config.dto;

import java.util.List;

public class ProviderConfigDtoV1 {
	// Required settings

	// OIDC provider issuer url
	public String providerUrl;

	// OIDC client id
	public String clientId;

	// Optional settings

	// OIDC scopes to request
	// At minimum, openid is required.
	// offline_access is required to get refresh tokens to automatically keep the players session alive.
	public List<String> scopes = List.of("openid", "profile", "offline_access");

	// OIDC claim to get roles
	// If specified, this claim will be used to assign roles to players.
	public String rolesClaim = null;

	public static ProviderConfigDtoV1 getExample() {
		ProviderConfigDtoV1 dto = new ProviderConfigDtoV1();
		dto.providerUrl = "http://idp.example.com";
		dto.clientId = "example_provider";
	    dto.scopes = List.of("openid", "groups", "profile", "offline_access");
	    dto.rolesClaim = "groups";
	    return dto;
	}
}