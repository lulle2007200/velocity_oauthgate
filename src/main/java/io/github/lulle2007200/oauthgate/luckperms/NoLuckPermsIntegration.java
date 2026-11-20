package io.github.lulle2007200.oauthgate.luckperms;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

public class NoLuckPermsIntegration implements ILuckPermsIntegration {

	@Override
	public CompletableFuture<Void> updateUser(UUID uuid, Consumer<IUser> user) {
		return CompletableFuture.completedFuture(null);
	}

}