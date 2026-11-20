package io.github.lulle2007200.oauthgate.oauth;

import java.util.Optional;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class OidcException extends RuntimeException {
	private final ErrorObject error;

	public OidcException(Throwable cause) {
		this.error = null;
		super(cause);
	}

	public OidcException(String message) {
		this.error = null;
		super(message);
	}

	public OidcException(String message, Throwable cause) {
		this.error = null;
		super(message, cause);
	}

	public OidcException(ErrorObject error) {
		this.error = error;
		super(error.getDescription());
	}

	public String getCode() {
		return Optional.ofNullable(error).map(ErrorObject::getCode).orElse(null);
	}
}
