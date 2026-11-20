package io.github.lulle2007200.oauthgate.config;

public class ConfigException extends  RuntimeException {
	public ConfigException(String message) {
		super(message);
	}

	public ConfigException(String message, Throwable cause) {
		super(message, cause);
	}

	public ConfigException(Throwable cause) {
		super(cause);
	}
}