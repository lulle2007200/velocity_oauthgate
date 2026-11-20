package io.github.lulle2007200.oauthgate.sessions;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

import io.github.lulle2007200.oauthgate.oauth.OidcProviderId;

public record Session(
    UUID uuid, 
    String username,
    Subject subject, 

    Set<String> roles,

    Instant issuedAt,
    Optional<Instant> expiresAt,
    
    Optional<RefreshToken> refreshToken,
    AccessToken accessToken,
    OidcProviderId providerId
) {}