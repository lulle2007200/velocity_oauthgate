package io.github.lulle2007200.oauthgate.config.dto;

import java.util.List;

public class BypasserConfigDtoV1 {
	// Optional settings

	// Roles to assign to the player
	public List<String> roles = List.of();

	public static BypasserConfigDtoV1 getExample() {
		BypasserConfigDtoV1 dto = new BypasserConfigDtoV1();
		dto.roles = List.of("moderator", "survival");
		return dto; 
	}
}