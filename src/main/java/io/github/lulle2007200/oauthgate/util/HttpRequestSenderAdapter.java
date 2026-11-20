package io.github.lulle2007200.oauthgate.util;

import java.io.IOException;
import java.net.http.HttpClient;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.ReadOnlyHTTPRequest;
import com.nimbusds.oauth2.sdk.http.ReadOnlyHTTPResponse;

public class HttpRequestSenderAdapter implements HTTPRequestSender {
	private final HttpClient httpClient;

	public HttpRequestSenderAdapter(HttpClient httpClient) {
		this.httpClient = Objects.requireNonNull(httpClient);
	}

	@Override
	public ReadOnlyHTTPResponse send(ReadOnlyHTTPRequest httpRequest) throws IOException {
		// TODO: Actually use the passed HttpClient
		return ((HTTPRequest)httpRequest).send();
	}
}