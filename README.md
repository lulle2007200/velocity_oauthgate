# OAuthGate

A Velocity proxy plugin that gates access to your Minecraft servers behind **OpenID Connect (OIDC) login**.

Players authenticate in their browser through configured identity provider (IdP), for example Authelia or  Keycloak. Once linked, their session is kept alive automatically, and their roles are synced into LuckPerms, if installed.

## Features

- **OIDC login gate**: Unauthenticated players are kicked and shown a login link. Once they completed the login, they can rejoin.
- **Session persistence & auto-refresh**: While a player is active, their session is kept alive, if the chosen IdP issues refresh tokens. If refreshing the session fails, the player is kicked and asked to login again.
- **Role synchronization**: Roles can be read from a configurable claim and are temporarily added to the users LuckPerms user and revoked once their session runs out. All roles are prefixed with `oauthgate_role_`. In addition, all linked players get the `oauthgate_linked` role.
- **Bypass list**: If players are added to the bypass list, OIDC authentication is skipped. Instead, they are marked as linked and may be assigned a preconfigured set of roles.

## Requirements

- Velocity 4.3+.
- Java 25.
- LuckPerms (Optional, only for role syncing).

## Installation

1. Drop jar to `plugins/` directory.
2. Add an identity provider to the config in `plugins/oauthgate.json`, use `oauthgate.template.json` as a template, or start the proxy once to generate a default configuration.
3. Restart the proxy.

## Configuration

All settings live in `plugins/oauthgate.json`. See the **annotated template [`oauthgate.template.json`](oauthgate.template.json)** for a complete description of every option.

Example config:

```json
{
  "authCallbackBaseUrl": "http://auth.example.com",
  "providers": {
    "Authelia": {
      "providerUrl": "https://auth.example.com",
      "clientId": "minecraft",
      "scopes": ["openid", "groups", "profile", "offline_access"],
      "rolesClaim": "groups"
    }
  },
  "sessionStoreType": "file",
  "maxSessionLifetime": 43200
}
```


## Building

```bash
./gradlew shadowJar
```

The bundled jar is produced at `build/libs/`.



## Note: 
This is not production ready and basically a prototype. That being said, it works well enough.