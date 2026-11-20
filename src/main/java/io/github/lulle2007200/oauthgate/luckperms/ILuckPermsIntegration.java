package io.github.lulle2007200.oauthgate.luckperms;

import java.time.Instant;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

public interface ILuckPermsIntegration {
	public static interface IUser {
		void addRoles(Collection<String> roles, Optional<Instant> expiresAt);
		void addRole(String role, Optional<Instant> expiresAt);

		void removeRoles(Collection<String> roles);
		void removeRole(String role);

		void addPermissions(Collection<String> permissions, Optional<Instant> epxiresAt);
		void addPermission(String permission, Optional<Instant> epxiresAt);

		void removePermissions(Collection<String> permissions);
		void removePermission(String permission);

		void setLinked(boolean linked);
	}

	CompletableFuture<Void> updateUser(UUID uuid, Consumer<IUser> user);
}