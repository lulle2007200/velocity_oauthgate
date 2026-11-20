package io.github.lulle2007200.oauthgate.sessions;

public class SessionException extends RuntimeException {
	public SessionException(String message) {
		super(message);
	}

	public SessionException(String message, Throwable cause) {
		super(message, cause);
	}

	public SessionException(Throwable cause) {
		super(cause);
	}
}