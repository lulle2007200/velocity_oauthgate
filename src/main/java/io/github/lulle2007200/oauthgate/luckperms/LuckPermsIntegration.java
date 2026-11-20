package io.github.lulle2007200.oauthgate.luckperms;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

import net.luckperms.api.LuckPerms;
import net.luckperms.api.model.data.NodeMap;
import net.luckperms.api.model.user.User;
import net.luckperms.api.node.NodeType;
import net.luckperms.api.node.types.InheritanceNode;

public class LuckPermsIntegration implements ILuckPermsIntegration {
	private class UserImpl implements IUser {
		private final User user;
		private final LuckPermsIntegration luckPerms;

		public UserImpl(User user, LuckPermsIntegration luckPerms) {
			this.user = Objects.requireNonNull(user);
			this.luckPerms = Objects.requireNonNull(luckPerms);
		}

		private void addRoleUnmapped(NodeMap data, String role, Optional<Duration> duration) {
			InheritanceNode.Builder builder = InheritanceNode.builder();
			builder.group(role);
			if (duration.isPresent()) {
				builder.expiry(duration.get());
			}
			data.add(builder.build());
		}

		private void addRole(NodeMap data, String role, Optional<Duration> duration) {
			String mappedRole = luckPerms.mapRole(role);
			addRoleUnmapped(data, mappedRole, duration);
		}

		private void removeRoleUnmapped(NodeMap data, String role) {
			data.clear(NodeType.INHERITANCE.predicate(node -> {
				return node.getGroupName().equals(role);
			}));
		}

		private void removeRole(NodeMap data, String role) {
			String mappedRole = luckPerms.mapRole(role);
			removeRoleUnmapped(data, mappedRole);
		}

		private Optional<Duration> getDuration(Optional<Instant> expiresAt) {
			return expiresAt.map(instant -> {
				return Duration.between(Instant.now(), instant);
			})
			.filter(Duration::isPositive);
		}

		@Override
		public void addRoles(Collection<String> roles, Optional<Instant> expiresAt) {
			Optional<Duration> duration = getDuration(expiresAt);
			NodeMap data = user.data();
			roles.forEach(role -> {
				addRole(data, role, duration);
			});
		}

		@Override
		public void addRole(String role, Optional<Instant> expiresAt) {
			addRole(user.data(), role, getDuration(expiresAt));
		}

		@Override
		public void removeRoles(Collection<String> roles) {
			NodeMap data = user.data();
			roles.forEach(role -> {
				removeRole(data, role);
			});
		}

		@Override
		public void removeRole(String role) {
			removeRole(user.data(), role);
		}

		@Override
		public void addPermissions(Collection<String> permissions, Optional<Instant> epxiresAt) {
			// TODO Auto-generated method stub
			throw new UnsupportedOperationException("Unimplemented method 'addPermissions'");
		}

		@Override
		public void addPermission(String permission, Optional<Instant> epxiresAt) {
			// TODO Auto-generated method stub
			throw new UnsupportedOperationException("Unimplemented method 'addPermission'");
		}

		@Override
		public void removePermissions(Collection<String> permissions) {
			// TODO Auto-generated method stub
			throw new UnsupportedOperationException("Unimplemented method 'removePermissions'");
		}

		@Override
		public void removePermission(String permission) {
			// TODO Auto-generated method stub
			throw new UnsupportedOperationException("Unimplemented method 'removePermission'");
		}

		@Override
		public void setLinked(boolean linked) {
			// TODO: name for role indicating linked profile
			String role = luckPerms.mapRole("oauthgate_linked");
			if (linked) {
				addRoleUnmapped(user.data(), role, null);
			} else {
				removeRoleUnmapped(user.data(), role);
			}
		}} 

	private final LuckPerms luckPerms;

	public LuckPermsIntegration(LuckPerms luckPerms) {
		this.luckPerms = Objects.requireNonNull(luckPerms);
	}

	@Override
	public CompletableFuture<Void> updateUser(UUID uuid, Consumer<IUser> action) {
		return luckPerms.getUserManager().modifyUser(uuid, user -> {
			UserImpl userImpl = new UserImpl(user, this);
			action.accept(userImpl);
		});
	}

	protected String mapRole(String role) {
		// TODO: properly sanitize role names
		// TODO: per-provider config for how to map oidc <-> luckperms roles
		//       for now, just add prefix
		String prefix = "oauthgate_role_";
		return prefix + role;
	}
}
