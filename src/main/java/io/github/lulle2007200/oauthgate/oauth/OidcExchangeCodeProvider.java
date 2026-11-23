package io.github.lulle2007200.oauthgate.oauth;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import com.google.common.html.HtmlEscapers;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

public class OidcExchangeCodeProvider implements IOidcExchangeCodeProvider {
    public static class Builder {
        private URI baseUrl;
        private Duration loginTimeout = Duration.ofSeconds(120);
        private HttpClient httpClient;
        private Duration readTimeout = Duration.ZERO;
        private Duration connectTimeout = Duration.ZERO;
        private InetSocketAddress bindAddress = new InetSocketAddress("0.0.0.0", 80);

        public Builder withHttpClient(HttpClient httpClient) {
            this.httpClient = Objects.requireNonNull(httpClient);
            return this;
        }

        public Builder withLoginTimeout(Duration loginTimeout) {
            this.loginTimeout = validateDuration(loginTimeout);
            return this;
        }

        public Builder withBaseUrl(URI baseUrl) {
            this.baseUrl = Objects.requireNonNull(baseUrl);
            return this;
        }

        public Builder withReadTimeout(Duration readTimeout) {
            this.readTimeout = validateDuration(readTimeout);
            return this;
        }

        public Builder withConnectTimeout(Duration connectTimeout) {
            this.connectTimeout = validateDuration(connectTimeout);
            return this;
        }

        public Builder withBindAddress(InetSocketAddress bindAddress) {
            this.bindAddress = Objects.requireNonNull(bindAddress);
            return this;
        }

        public OidcExchangeCodeProvider build() {
            return new OidcExchangeCodeProvider(baseUrl,
                                                bindAddress,
                                                loginTimeout, 
                                                httpClient, 
                                                readTimeout, 
                                                connectTimeout);
        }

        private Duration validateDuration(Duration ttl) {
            ttl = Objects.requireNonNull(ttl);
            if (ttl.isNegative()) {
                throw new IllegalArgumentException("Ttl must be non negative");
            }
            return ttl;
        }
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    private record PendingRequest(
        UUID uuid,
        String username,
        CodeChallenge codeChallenge,
        CodeChallengeMethod method,
        List<OidcProvider> providers,
        CompletableFuture<OidcExchangeCodeRequestResult> result
    ) {}

    private static final String pageStyles = """
        <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
          background: linear-gradient(160deg, #0f172a 0%, #1e293b 100%);
          color: #e2e8f0;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 1rem;
        }
        .card {
          background: #ffffff;
          color: #0f172a;
          border-radius: 16px;
          box-shadow: 0 24px 60px rgba(0, 0, 0, .45);
          padding: 2.25rem 2rem;
          width: 100%;
        }
        h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: .35rem; }
        .subtitle { color: #64748b; font-size: .95rem; margin-bottom: 1.75rem; }
        .providers { display: flex; flex-direction: column; gap: .75rem; }
        .provider {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: .9rem 1.1rem;
          border: 1px solid #e2e8f0;
          border-radius: 12px;
          text-decoration: none;
          color: #0f172a;
          font-weight: 600;
          transition: all .15s ease;
        }
        .provider:hover {
          border-color: #6366f1;
          background: #eef2ff;
          transform: translateY(-1px);
        }
        .provider-arrow { color: #6366f1; font-size: 1.1rem; }
        </style>""";

    private static final String signInPageHtml = """
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Sign in</title>
                %STYLES%
            </head>
                <body>
                    <main class="card" style="max-width:420px;margin:8vh auto;">
                        <h1>Sign in</h1>
                        <p class="subtitle">Choose how you want to sign in</p>
                        <div class="providers">
                            %PROVIDERS%
                        </div>
                    </main>
                </body>
        </html>""";

    private static final String providerLinkHtml = """
        <a class="provider" href="%HREF%">
            <span class="provider-name">%NAME%</span>
            <span class="provider-arrow">→</span>
        </a>""";

    private static final String donePageHtml = """
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Sign-in complete</title>
                %STYLES%
            </head>
            <body>
                <main class="card" style="max-width:380px;margin:8vh auto;text-align:center;">
                    <h1>You're all set</h1>
                    <p class="subtitle">You can close this tab and return to the game.</p>
                </main>
            </body>
        </html>""";

    private static final String errorPageHtml = """
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Sign-in failed</title>
                %STYLES%
            </head>
            <body>
                <main class="card" style="max-width:380px;margin:8vh auto;text-align:center;">
                    <h1>An error occured</h1>
                    <p class="subtitle">%ERROR%</p>
                </main>
            </body>
        </html>""";

    private static final char[] shortCodeAlphabet = "abcdefghkopqrstuxyz".toCharArray();
    private static final SecureRandom random = new SecureRandom();

    private final HttpClient httpClient;
    private final Duration requestTtl;

    private final Duration readTimeout;
    private final Duration connectTimeout;

    private final URI callbackUrl;
    private final URI shortLinkBaseUrl;
    private final URI authBaseUrl;

    private final Map<String, PendingRequest> pending = new ConcurrentHashMap<>();
    private final Map<OidcProviderId, OidcDiscovery> discoveries = new ConcurrentHashMap<>();
    private final HttpServer server;

    public OidcExchangeCodeProvider(URI baseUrl,
                                    InetSocketAddress bindAddress,
                                    Duration requestTtl,
                                    HttpClient httpClient,
                                    Duration readTimeout,
                                    Duration connectTimeout) {
        baseUrl = Objects.requireNonNull(baseUrl);
        String basePath = baseUrl.getPath();
        if (basePath == null || basePath.isEmpty()) {
            basePath = "/";
        } else if (!basePath.endsWith("/")) {
            basePath += "/";
        }

        try {
            baseUrl = new URI(baseUrl.getScheme(), 
                              baseUrl.getUserInfo(),
                              baseUrl.getHost(), 
                              baseUrl.getPort(),
                              basePath, 
                              baseUrl.getQuery(), 
                              baseUrl.getFragment());
        } catch (URISyntaxException ex) {
            throw new AssertionError(ex);
        }

        this.readTimeout = Objects.requireNonNull(readTimeout);
        this.connectTimeout = Objects.requireNonNull(connectTimeout);

        this.requestTtl = Objects.requireNonNull(requestTtl);
        this.httpClient = Objects.requireNonNull(httpClient);

        this.callbackUrl = baseUrl.resolve("callback");
        this.shortLinkBaseUrl = baseUrl.resolve("l/");
        this.authBaseUrl = baseUrl.resolve("auth/");

        try {
            this.server = HttpServer.create(Objects.requireNonNull(bindAddress), 0);
        } catch (IOException ex) {
            throw new OidcException("Failed to start HTTP server", ex);
        }
        server.createContext(basePath, this::dispatch);
        server.start();
    }

    @Override
    public OidcPendingExchangeCodeRequest getExchangeCode(String username,
                                                          UUID uuid,
                                                          CodeChallenge codeChallenge,
                                                          CodeChallengeMethod method,
                                                          List<OidcProvider> providers) {
        CompletableFuture<OidcExchangeCodeRequestResult> result = new CompletableFuture<>();
        PendingRequest request = new PendingRequest(uuid, username, codeChallenge, method, providers, result);
        String shortId = registerPendingRequest(request);

        result.orTimeout(requestTtl.toMillis(), TimeUnit.MILLISECONDS)
            .whenComplete((r, t) -> pending.remove(shortId));

        URI shortUrl = shortLinkBaseUrl.resolve(shortId);
        return new OidcPendingExchangeCodeRequest(
            shortUrl, 
            result, 
            () -> {
                PendingRequest removed = pending.remove(shortId);
                if (removed != null) {
                    removed.result().cancel(true);
            }
        });
    }

    @Override
    public URI getCallbackUrl() {
        return callbackUrl;
    }

    private String registerPendingRequest(PendingRequest request) {
        while (true) {
            String shortId = makeShortId();
            if (pending.putIfAbsent(shortId, request) == null) {
                return shortId;
            }
        }
    }

    private static String makeShortId() {
        StringBuilder sb = new StringBuilder(8);
        for (int i = 0; i < 8; i++) {
            sb.append(shortCodeAlphabet[random.nextInt(shortCodeAlphabet.length)]);
        }
        return sb.toString();
    }

    private void notFound(HttpExchange exchange) throws IOException {
        authFailed(exchange, 404, "Not found");
    }

    private void linkExpired(HttpExchange exchange) throws IOException {
        authFailed(exchange, 410, "This link has expired");
    }

    private void missingParam(HttpExchange exchange, String param) throws IOException {
        authFailed(exchange, 400, "Missing " + param + " parameter");
    }

    private void invalidParam(HttpExchange exchange, String param) throws IOException {
        authFailed(exchange, 400, "Invalid " + param + " parameter");
    }

    private void authFailed(HttpExchange exchange, int code, String message) throws IOException {
        String html = errorPageHtml
            .replace("%ERROR%", message)
            .replace("%STYLES%", pageStyles);
        sendText(exchange, code, "text/html", html);
    }

    private void dispatch(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        try {
            if (path.startsWith(authBaseUrl.getPath())) {
                handleAuthorize(exchange);
            } else if (path.equals(callbackUrl.getPath())) {
                handleCallback(exchange);
            } else if (path.startsWith(shortLinkBaseUrl.getPath())) {
                handleLink(exchange);
            } else {
                notFound(exchange);
            }
        } finally {
            exchange.close();
        }
    }

    private void handleLink(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String id = path.substring(path.lastIndexOf("/") + 1);

        PendingRequest request = pending.get(id);
        if (request == null) {
            linkExpired(exchange);
            return;
        }

        StringBuilder providers = new StringBuilder();
        int i = 0;
        for (OidcProvider provider : request.providers()) {
            URI target = authBaseUrl.resolve(id + "/" + i);
            providers.append(providerLinkHtml
                .replace("%HREF%", HtmlEscapers.htmlEscaper().escape(target.getPath()))
                .replace("%NAME%", HtmlEscapers.htmlEscaper().escape(provider.issuerFriendlyName())));
            i++;
        }

        String html = signInPageHtml
            .replace("%STYLES%", pageStyles)
            .replace("%PROVIDERS%", providers.toString());

        sendText(exchange, 200, "text/html", html);
    }

    private OidcDiscovery getDiscovery(OidcProvider provider) {
        OidcProviderId providerId = new OidcProviderId(provider.issuer(),
                                                       provider.clientId());
        return discoveries.computeIfAbsent(providerId,
            _ -> OidcDiscovery.newBuilder()
                .withIssuer(provider.issuer())
                .withHttpClient(httpClient)
                .withConnectTimeout(connectTimeout)
                .withReadTimeout(readTimeout)
                .build());
    }

    private void handleAuthorize(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String rest = path.substring(authBaseUrl.getPath().length());

        String[] parts = rest.split("/", -1);

        if (parts.length != 2) {
            notFound(exchange);
            return;
        }

        String id = parts[0];
        int idx = Integer.parseInt(parts[1]);

        PendingRequest request = pending.get(id);
        if (request == null) {
            linkExpired(exchange);
            return;
        }

        OidcProvider provider = request.providers().get(idx);
        OidcDiscovery discovery = getDiscovery(provider);

        URI authorizeEndpoint = discovery.getMetadata().join().getAuthorizationEndpointURI();

        AuthorizationRequest authRequest = applyPkce(
                new AuthorizationRequest.Builder(ResponseType.CODE, provider.clientId())
                    .redirectionURI(callbackUrl)
                    .scope(provider.scope())
                    .state(new State(id + ":" + idx)),
                request.codeChallenge,
                request.method())
            .endpointURI(authorizeEndpoint)
            .build();

        exchange.getResponseHeaders().set("Location", authRequest.toURI().toString());
        exchange.sendResponseHeaders(302, -1);
    }

    private void handleCallback(HttpExchange exchange) throws IOException {
        Map<String, String> query = parseQuery(exchange.getRequestURI().getRawQuery());
        String state = query.get("state");
        if (state == null) {
            missingParam(exchange, "state");
            return;
        }

        String[] parts = state.split(":", -1);
        if (parts.length != 2) {
            invalidParam(exchange, "state");
            return;
        }

        // TODO: save state on the pending request when redirecting and make sure we get back the same state

        String id = parts[0];
        PendingRequest request = pending.remove(id);
        if (request == null) {
            linkExpired(exchange);
            return;
        }

        int idx;
        try {
            idx = Integer.parseInt(parts[1]);
        } catch (NumberFormatException ex) {
            invalidParam(exchange, "state");
            return;
        }

        if (idx < 0 || idx >= request.providers().size()) {
            invalidParam(exchange, "state");
            return;
        }   

        if (query.containsKey("error")) {
            String error = query.get("error");
            request.result().completeExceptionally(new OidcException("Authorization failed: " + error));
            authFailed(exchange, 400, error);
            return;
        }

        String code = query.get("code");
        if (code == null) {
            missingParam(exchange, "code");
            return;
        }

        OidcProvider provider = request.providers().get(idx);
        OidcProviderId providerId = new OidcProviderId(provider.issuer(), provider.clientId());

        request.result().complete(new OidcExchangeCodeRequestResult(new AuthorizationCode(code), providerId));

        sendText(exchange, 200, "text/html", donePageHtml.replace("%STYLES%", pageStyles));
    }

    @SuppressWarnings("deprecation")
    private static AuthorizationRequest.Builder applyPkce(AuthorizationRequest.Builder builder,
                                                         CodeChallenge codeChallenge,
                                                         CodeChallengeMethod method) {
        return builder.codeChallenge(codeChallenge, method);
    }

    private static void sendText(HttpExchange exchange, 
                                 int status, 
                                 String contentType, 
                                 String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType + "; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> map = new HashMap<>();
        if (rawQuery == null) return map;
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) continue;
            String k = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
            String v = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            map.put(k, v);
        }
        return map;
    }
}
