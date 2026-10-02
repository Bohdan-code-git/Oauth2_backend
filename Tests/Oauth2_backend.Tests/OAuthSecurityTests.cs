using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.AspNetCore.Hosting;
using Xunit;

public sealed class OAuthSecurityTests
{
    [Fact]
    public void UnconfiguredDemoDoesNotInventProviderIdentitiesOrSuccessfulRequests()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["App:PublicOrigin"] = "http://localhost:5223",
                ["App:FrontendOrigin"] = "http://localhost:4200"
            })
            .Build();
        var providers = new OAuthProviderClient(configuration, new StubHttpClientFactory(), TimeProvider.System);
        var service = new ConnectionService(
            providers,
            TimeProvider.System);
        var session = new WorkspaceSession("demo-workspace-id", "demo-csrf-token", TimeProvider.System.GetUtcNow());

        var snapshot = service.GetSnapshot(session);

        Assert.True(snapshot.DemoMode);
        Assert.Equal(3, snapshot.Connections.Count);
        Assert.All(snapshot.Connections, connection =>
        {
            Assert.False(connection.Configured);
            Assert.Equal("not_configured", connection.Status);
            Assert.Null(connection.Profile);
            Assert.Null(connection.ConnectedAt);
            Assert.Null(connection.LastSyncedAt);
        });
    }

    [Fact]
    public void PkceChallengeUsesBase64UrlSha256()
    {
        const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        var challenge = Pkce.CreateChallenge(verifier);

        Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge);
        Assert.DoesNotContain("=", challenge);
    }

    [Fact]
    public void StateIsProviderBoundExpiresAndCanOnlyBeConsumedOnce()
    {
        var now = new DateTimeOffset(2026, 9, 30, 12, 0, 0, TimeSpan.Zero);
        var states = new OAuthStateTransactions();
        var transaction = states.Create(ProviderId.Github, now);

        Assert.Equal(43, transaction.State.Length);
        Assert.Equal(43, transaction.CodeVerifier?.Length);
        Assert.False(states.TryConsume(transaction.State, ProviderId.Google, now, out _));
        Assert.True(states.TryConsume(transaction.State, ProviderId.Github, now, out var consumed));
        Assert.Equal(transaction, consumed);
        Assert.False(states.TryConsume(transaction.State, ProviderId.Github, now, out _));
    }

    [Fact]
    public void DiscordStateIsSingleUseAndDoesNotCreateAnUndocumentedPkceVerifier()
    {
        var now = new DateTimeOffset(2026, 9, 30, 12, 0, 0, TimeSpan.Zero);
        var states = new OAuthStateTransactions();
        var transaction = states.Create(ProviderId.Discord, now, usePkce: false);

        Assert.Null(transaction.CodeVerifier);
        Assert.False(states.TryConsume(transaction.State, ProviderId.Github, now, out _));
        Assert.True(states.TryConsume(transaction.State, ProviderId.Discord, now, out var consumed));
        Assert.Equal(transaction, consumed);
        Assert.False(states.TryConsume(transaction.State, ProviderId.Discord, now, out _));
    }

    [Fact]
    public void ExpiredKnownStateIsDistinguishedFromUnknownState()
    {
        var now = new DateTimeOffset(2026, 9, 30, 12, 0, 0, TimeSpan.Zero);
        var states = new OAuthStateTransactions();
        var transaction = states.Create(ProviderId.Google, now);
        states.Create(ProviderId.Github, now.AddMinutes(11));

        Assert.False(states.TryConsume(
            transaction.State,
            ProviderId.Github,
            now.AddMinutes(11),
            out _,
            out var knownExpired));
        Assert.False(knownExpired);

        Assert.False(states.TryConsume(
            transaction.State,
            ProviderId.Google,
            now.AddMinutes(11),
            out _,
            out knownExpired));
        Assert.True(knownExpired);

        Assert.False(states.TryConsume(
            "attacker-supplied-state",
            ProviderId.Google,
            now.AddMinutes(11),
            out _,
            out knownExpired));
        Assert.False(knownExpired);

        Assert.False(states.TryConsume(
            transaction.State,
            ProviderId.Google,
            now.AddMinutes(11),
            out _,
            out knownExpired));
        Assert.False(knownExpired);
    }

    [Fact]
    public void PendingOAuthTransactionsAreBoundedPerWorkspace()
    {
        var now = new DateTimeOffset(2026, 9, 30, 12, 0, 0, TimeSpan.Zero);
        var states = new OAuthStateTransactions();

        for (var attempt = 0; attempt < OAuthStateTransactions.MaximumPendingTransactions; attempt++)
            states.Create(ProviderId.Google, now);

        Assert.Throws<OAuthTransactionCapacityException>(() => states.Create(ProviderId.Google, now));
    }

    [Theory]
    [InlineData("access_denied", "access_denied")]
    [InlineData("server_error", "provider_error")]
    [InlineData("<script>do-not-reflect</script>", "provider_error")]
    [InlineData(null, "provider_error")]
    public void ProviderErrorsAreReducedToSafeReasons(string? providerError, string expected)
    {
        Assert.Equal(expected, OAuthCallbackErrors.Map(providerError));
    }

    [Fact]
    public void PublicConnectionDtoDoesNotSerializeProviderTokens()
    {
        const string accessSentinel = "access-token-must-not-escape";
        const string refreshSentinel = "refresh-token-must-not-escape";
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);
        var storedConnection = new StoredProviderConnection
        {
            Provider = ProviderId.Google,
            AccessToken = accessSentinel,
            RefreshToken = refreshSentinel,
            AccessTokenExpiresAt = expiresAt,
            GrantedScopes = ["openid", "email", "profile"],
            ConnectedAt = DateTimeOffset.UtcNow
        };
        var response = new ConnectionsResponse(
            false,
            DateTimeOffset.UtcNow,
            [
                new ConnectionDto(
                    "google",
                    "Google",
                    "connected",
                    true,
                    new ProviderProfile("Sample", "sample@example.test", "sample@example.test", null, null),
                    storedConnection.ConnectedAt,
                    null,
                    null)
                {
                    AccessTokenExpiresAt = storedConnection.AccessTokenExpiresAt,
                    CanRefreshAccessToken = !string.IsNullOrWhiteSpace(storedConnection.RefreshToken),
                    GrantedScopes = storedConnection.GrantedScopes
                }
            ]);

        var json = JsonSerializer.Serialize(response, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.DoesNotContain(accessSentinel, json, StringComparison.Ordinal);
        Assert.DoesNotContain(refreshSentinel, json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"accessToken\":", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("\"refreshToken\":", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"accessTokenExpiresAt\":", json, StringComparison.Ordinal);
        Assert.Contains("\"canRefreshAccessToken\":true", json, StringComparison.Ordinal);
        Assert.Contains("\"grantedScopes\":[\"openid\",\"email\",\"profile\"]", json, StringComparison.Ordinal);
    }

    [Fact]
    public void AuthorizationUrlsUseStatePkceAndOnlyTheRequiredScopes()
    {
        var settings = new Dictionary<string, string?>
        {
            ["App:PublicOrigin"] = "http://localhost:5223",
            ["App:FrontendOrigin"] = "http://localhost:4200",
            ["OAuth:Github:ClientId"] = "github-client-id",
            ["OAuth:Github:ClientSecret"] = "github-client-secret",
            ["OAuth:Google:ClientId"] = "google-client-id",
            ["OAuth:Google:ClientSecret"] = "google-client-secret",
            ["OAuth:Discord:ClientId"] = "discord-client-id",
            ["OAuth:Discord:ClientSecret"] = "discord-client-secret"
        };
        var client = new OAuthProviderClient(
            new ConfigurationBuilder().AddInMemoryCollection(settings).Build(),
            new StubHttpClientFactory(),
            TimeProvider.System);
        var transaction = new OAuthStateTransactions().Create(
            ProviderId.Github,
            DateTimeOffset.UtcNow);
        var challenge = Pkce.CreateChallenge(transaction.CodeVerifier!);

        var github = ParseQuery(client.BuildAuthorizationUrl(
            ProviderId.Github,
            transaction.State,
            challenge));
        var google = ParseQuery(client.BuildAuthorizationUrl(
            ProviderId.Google,
            transaction.State,
            challenge));
        var discord = ParseQuery(client.BuildAuthorizationUrl(
            ProviderId.Discord,
            transaction.State,
            null));
        Assert.Equal(transaction.State, github["state"]);
        Assert.Equal("code", google["response_type"]);
        Assert.Equal("S256", github["code_challenge_method"]);
        Assert.Equal(challenge, github["code_challenge"]);
        Assert.Equal("offline_access", github["scope"]);
        Assert.Equal("openid email profile", google["scope"]);
        Assert.Equal("false", google["include_granted_scopes"]);
        Assert.Equal("select_account consent", google["prompt"]);
        Assert.Equal("identify", discord["scope"]);
        Assert.Equal("consent", discord["prompt"]);
        Assert.DoesNotContain("code_challenge", discord.Keys, StringComparer.Ordinal);
        Assert.DoesNotContain("code_challenge_method", discord.Keys, StringComparer.Ordinal);
        Assert.Equal("http://localhost:5223/api/oauth/discord/callback", discord["redirect_uri"]);
        Assert.Equal(
            "http://localhost:5223/api/oauth/github/callback",
            github["redirect_uri"]);
        Assert.DoesNotContain("client_secret", github.Keys, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("access_token", github.Keys, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("refresh_token", github.Keys, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("client_secret", discord.Keys, StringComparer.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(ProviderId.Github, "{\"access_token\":\"test-token\",\"scope\":\"repo,read:user\"}")]
    [InlineData(ProviderId.Google, "{\"access_token\":\"test-token\",\"scope\":\"openid email profile https://www.googleapis.com/auth/drive.readonly\"}")]
    [InlineData(ProviderId.Discord, "{\"access_token\":\"test-token\",\"scope\":\"identify connections\"}")]
    public async Task TokenExchangeRejectsScopesOutsideTheSelectedProviderContract(
        ProviderId provider,
        string responseBody)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["App:PublicOrigin"] = "http://localhost:5223",
                ["App:FrontendOrigin"] = "http://localhost:4200",
                ["OAuth:Google:ClientId"] = "google-client-id",
                ["OAuth:Google:ClientSecret"] = "google-client-secret",
                ["OAuth:Github:ClientId"] = "github-client-id",
                ["OAuth:Github:ClientSecret"] = "github-client-secret",
                ["OAuth:Discord:ClientId"] = "discord-client-id",
                ["OAuth:Discord:ClientSecret"] = "discord-client-secret"
            })
            .Build();
        var client = new OAuthProviderClient(
            configuration,
            new StubHttpClientFactory(new JsonResponseHandler(HttpStatusCode.OK, responseBody)),
            TimeProvider.System);

        var error = await Assert.ThrowsAsync<ProviderRequestException>(() =>
            client.ExchangeCodeAsync(
                provider,
                "authorization-code",
                provider == ProviderId.Discord ? null : new string('v', 43)));

        Assert.Equal("unexpected_provider_scopes", error.Reason);
        Assert.False(error.RequiresAuthorization);
    }

    [Fact]
    public async Task DiscordCodeExchangeRejectsGrantWithoutIdentifyScope()
    {
        var client = CreateProviderClient(new JsonResponseHandler(
            HttpStatusCode.OK,
            "{\"access_token\":\"test-token\",\"scope\":\"\"}"));

        var error = await Assert.ThrowsAsync<ProviderRequestException>(() =>
            client.ExchangeCodeAsync(ProviderId.Discord, "authorization-code", null));

        Assert.Equal("missing_required_scopes", error.Reason);
        Assert.False(error.RequiresAuthorization);
    }

    [Theory]
    [InlineData(
        ProviderId.Google,
        "{\"error\":\"insufficient_scope\"}",
        "insufficient_permissions",
        true)]
    [InlineData(
        ProviderId.Discord,
        "null",
        "provider_forbidden",
        false)]
    [InlineData(
        ProviderId.Github,
        "{\"message\":\"API rate limit exceeded\"}",
        "provider_forbidden",
        false)]
    public async Task ForbiddenProviderResponsesAreClassifiedWithoutMistakingLimitsForRevokedConsent(
        ProviderId provider,
        string body,
        string expectedReason,
        bool requiresAuthorization)
    {
        var client = CreateProviderClient(new JsonResponseHandler(HttpStatusCode.Forbidden, body));

        var error = await Assert.ThrowsAsync<ProviderRequestException>(() =>
            client.GetProfileAsync(provider, "access-token-test"));

        Assert.Equal(expectedReason, error.Reason);
        Assert.Equal(requiresAuthorization, error.RequiresAuthorization);
    }

    [Fact]
    public async Task GithubCodeExchangeRejectsUnverifiablePriorScopeGrant()
    {
        var client = CreateProviderClient(new JsonResponseHandler(
            HttpStatusCode.OK,
            "{\"access_token\":\"test-token\"}"));

        var error = await Assert.ThrowsAsync<ProviderRequestException>(() =>
            client.ExchangeCodeAsync(ProviderId.Github, "authorization-code", new string('v', 43)));

        Assert.Equal("unverified_provider_scopes", error.Reason);
        Assert.False(error.RequiresAuthorization);
    }

    [Fact]
    public async Task GithubProfileRequestPinsTheCurrentSupportedRestApiVersion()
    {
        var handler = new GithubProfileVersionHandler();
        var client = CreateProviderClient(handler);

        _ = await client.GetProfileAsync(ProviderId.Github, "github-access-token");

        Assert.Equal("2026-03-10", handler.ApiVersion);
    }

    [Fact]
    public async Task GoogleProfileKeepsTheStableSubjectSeparateFromTheEmailAddress()
    {
        var client = new OAuthProviderClient(
            new ConfigurationBuilder().Build(),
            new StubHttpClientFactory(new JsonResponseHandler(
                HttpStatusCode.OK,
                "{\"sub\":\"stable-google-sub\",\"email\":\"changed@example.test\","
                + "\"email_verified\":true,\"name\":\"Google User\"}")),
            TimeProvider.System);

        var profile = await client.GetProfileAsync(ProviderId.Google, "access-token-test");

        Assert.Equal("stable-google-sub", profile?.AccountKey);
        Assert.Equal("changed@example.test", profile?.Email);
        Assert.DoesNotContain("stable-google-sub", JsonSerializer.Serialize(profile), StringComparison.Ordinal);
        Assert.DoesNotContain("accountKey", JsonSerializer.Serialize(profile), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GoogleProfileWithoutOidcSubjectIsRejected()
    {
        var client = CreateProviderClient(new JsonResponseHandler(
            HttpStatusCode.OK,
            "{\"name\":\"Creator\",\"email\":\"creator@example.test\",\"email_verified\":true}"));

        var error = await Assert.ThrowsAsync<ProviderRequestException>(() =>
            client.GetProfileAsync(ProviderId.Google, "google-access-token-test-only"));

        Assert.Equal("invalid_provider_profile", error.Reason);
    }

    [Fact]
    public void ProviderContractPublishesSafeDetailsForTheAuthorizationFlow()
    {
        var settings = new Dictionary<string, string?>
        {
            ["App:PublicOrigin"] = "http://localhost:5223",
            ["App:FrontendOrigin"] = "http://localhost:4200",
            ["OAuth:Github:ClientId"] = "github-client-id",
            ["OAuth:Github:ClientSecret"] = "github-client-secret"
        };
        var client = new OAuthProviderClient(
            new ConfigurationBuilder().AddInMemoryCollection(settings).Build(),
            new StubHttpClientFactory(),
            TimeProvider.System);

        var github = client.GetPublicProviderConfiguration().Providers
            .Single(provider => provider.Provider == "github");
        var google = client.GetPublicProviderConfiguration().Providers
            .Single(provider => provider.Provider == "google");
        var discord = client.GetPublicProviderConfiguration().Providers
            .Single(provider => provider.Provider == "discord");

        Assert.True(github.Configured);
        Assert.False(google.Configured);
        Assert.Equal("S256", github.PkceMethod);
        Assert.Equal("https://github.com/login/oauth/access_token", github.TokenEndpoint);
        Assert.Equal("https://github.com/login/oauth/authorize", github.AuthorizationEndpoint);
        Assert.Equal("code", github.ResponseType);
        Assert.Equal(new[] { ("allow_signup", "false") }, github.AuthorizationParameters.Select(item => (item.Name, item.Value)));
        Assert.Equal("http://localhost:5223/api/oauth/github/callback", github.CallbackUri);
        Assert.Equal(["offline_access"], github.Scopes);
        Assert.Equal(["https://api.github.com/user"], github.ProfileEndpoints);
        Assert.Equal("https://oauth2.googleapis.com/token", google.TokenEndpoint);
        Assert.Equal("https://discord.com/api/oauth2/token", discord.TokenEndpoint);
        Assert.Equal("code", google.ResponseType);
        Assert.Equal(
            new[] { ("access_type", "offline"), ("include_granted_scopes", "false"), ("prompt", "select_account consent") },
            google.AuthorizationParameters.Select(item => (item.Name, item.Value)));
        Assert.Null(discord.PkceMethod);
        Assert.Equal(["identify"], discord.Scopes);
        Assert.Equal(["https://discord.com/api/v10/users/@me"], discord.ProfileEndpoints);
        var publicJson = JsonSerializer.Serialize(new[] { github, google, discord });
        Assert.DoesNotContain("client_id", publicJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("client_secret", publicJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("code_challenge", publicJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("code_verifier", publicJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("state", publicJson, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProviderIsNotConfiguredWhenFrontendAndCallbackHostsDiffer()
    {
        var settings = new Dictionary<string, string?>
        {
            ["App:PublicOrigin"] = "https://api.example.test",
            ["App:FrontendOrigin"] = "https://studio.example.test",
            ["OAuth:Github:ClientId"] = "github-client-id",
            ["OAuth:Github:ClientSecret"] = "github-client-secret"
        };
        var client = new OAuthProviderClient(
            new ConfigurationBuilder().AddInMemoryCollection(settings).Build(),
            new StubHttpClientFactory(),
            TimeProvider.System);

        var github = client.GetPublicProviderConfiguration().Providers
            .Single(provider => provider.Provider == "github");

        Assert.False(client.IsConfigured(ProviderId.Github));
        Assert.False(github.Configured);
        Assert.Null(github.CallbackUri);
        Assert.True(client.IsDemoMode());
    }

    [Fact]
    public void ProductionProviderIsNotConfiguredWhenOriginsUseDifferentPorts()
    {
        var settings = new Dictionary<string, string?>
        {
            ["App:PublicOrigin"] = "https://accounts.example.test:8443",
            ["App:FrontendOrigin"] = "https://accounts.example.test:9443",
            ["OAuth:Github:ClientId"] = "github-client-id",
            ["OAuth:Github:ClientSecret"] = "github-client-secret"
        };
        var client = new OAuthProviderClient(
            new ConfigurationBuilder().AddInMemoryCollection(settings).Build(),
            new StubHttpClientFactory(),
            TimeProvider.System);

        var github = client.GetPublicProviderConfiguration().Providers
            .Single(provider => provider.Provider == "github");

        Assert.False(client.IsConfigured(ProviderId.Github));
        Assert.False(github.Configured);
        Assert.Null(github.CallbackUri);
    }

    [Fact]
    public void RenderExternalUrlProvidesTheSingleOriginForHostedOAuthCallbacks()
    {
        var settings = new Dictionary<string, string?>
        {
            ["App:PublicOrigin"] = "http://localhost:5223",
            ["App:FrontendOrigin"] = "http://localhost:4300",
            ["RENDER_EXTERNAL_URL"] = "https://switchboard-demo.onrender.com",
            ["OAuth:Github:ClientId"] = "github-client-id",
            ["OAuth:Github:ClientSecret"] = "github-client-secret"
        };
        var client = new OAuthProviderClient(
            new ConfigurationBuilder().AddInMemoryCollection(settings).Build(),
            new StubHttpClientFactory(),
            TimeProvider.System);

        var github = client.GetPublicProviderConfiguration().Providers
            .Single(provider => provider.Provider == "github");

        Assert.True(github.Configured);
        Assert.Equal("https://switchboard-demo.onrender.com/api/oauth/github/callback", github.CallbackUri);
        Assert.Equal("https://switchboard-demo.onrender.com", client.GetFrontendOrigin());
    }

    [Fact]
    public void ExampleSecretPlaceholderCannotEnableALiveProvider()
    {
        var settings = new Dictionary<string, string?>
        {
            ["App:PublicOrigin"] = "http://localhost:5223",
            ["App:FrontendOrigin"] = "http://localhost:4200",
            ["OAuth:Google:ClientId"] = "configured-client-id",
            ["OAuth:Google:ClientSecret"] = "REPLACE_WITH_GOOGLE_WEB_CLIENT_SECRET"
        };
        var client = new OAuthProviderClient(
            new ConfigurationBuilder().AddInMemoryCollection(settings).Build(),
            new StubHttpClientFactory(),
            TimeProvider.System);

        Assert.False(client.IsConfigured(ProviderId.Google));
        Assert.True(client.IsDemoMode());
    }

    [Fact]
    public void CheckedInExampleUsesExplicitPlaceholdersForOAuthCredentials()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "appsettings.example.json");
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var providers = document.RootElement.GetProperty("OAuth");

        AssertCredentialPlaceholder(providers.GetProperty("Google"), "ClientId", "OAuth:Google:ClientId");
        AssertCredentialPlaceholder(providers.GetProperty("Google"), "ClientSecret", "OAuth:Google:ClientSecret");
        AssertCredentialPlaceholder(providers.GetProperty("Github"), "ClientId", "OAuth:Github:ClientId");
        AssertCredentialPlaceholder(providers.GetProperty("Github"), "ClientSecret", "OAuth:Github:ClientSecret");
        AssertCredentialPlaceholder(providers.GetProperty("Discord"), "ClientId", "OAuth:Discord:ClientId");
        AssertCredentialPlaceholder(providers.GetProperty("Discord"), "ClientSecret", "OAuth:Discord:ClientSecret");
    }

    [Fact]
    public async Task ExpiredGithubRefreshTokenRequiresReauthorization()
    {
        var settings = new Dictionary<string, string?>
        {
            ["OAuth:Github:ClientId"] = "github-client-id",
            ["OAuth:Github:ClientSecret"] = "github-client-secret"
        };
        var client = new OAuthProviderClient(
            new ConfigurationBuilder().AddInMemoryCollection(settings).Build(),
            new StubHttpClientFactory(new JsonResponseHandler(
                HttpStatusCode.BadRequest,
                "{\"error\":\"bad_refresh_token\"}")),
            TimeProvider.System);

        var error = await Assert.ThrowsAsync<ProviderRequestException>(() =>
            client.RefreshAsync(ProviderId.Github, "refresh-token-test-only"));

        Assert.Equal("authorization_required", error.Reason);
        Assert.True(error.RequiresAuthorization);
    }

    [Fact]
    public void ProviderRefreshRouteMatchesTheClientContract()
    {
        var method = typeof(ConnectionsController).GetMethod(nameof(ConnectionsController.RefreshProvider));
        var route = method?.GetCustomAttributes(typeof(HttpPostAttribute), inherit: true)
            .OfType<HttpPostAttribute>()
            .SingleOrDefault();

        Assert.Equal("{provider}/refresh", route?.Template);
    }

    [Fact]
    public void ProviderOAuthStartIsAPostThatCanRequireWorkspaceCsrf()
    {
        var method = typeof(OAuthController).GetMethod(nameof(OAuthController.Start));
        var post = method?.GetCustomAttributes(typeof(HttpPostAttribute), inherit: true)
            .OfType<HttpPostAttribute>()
            .SingleOrDefault();

        Assert.Equal("connections/{provider}/start", post?.Template);
        Assert.Empty(method?.GetCustomAttributes(typeof(HttpGetAttribute), inherit: true) ?? []);
    }

    [Fact]
    public void WorkspaceCookieIsOpaqueHttpOnlyAndSecureOutsideDevelopment()
    {
        var manager = new WorkspaceSessionManager(
            new InMemoryWorkspaceStore(TimeProvider.System),
            new TestWebHostEnvironment("Production"));
        var context = new DefaultHttpContext();

        var session = manager.GetOrCreate(context);
        Assert.NotNull(session);
        var cookie = context.Response.Headers.SetCookie.ToString();

        Assert.Contains("__Host-switchboard.sid=", cookie, StringComparison.Ordinal);
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("access-token", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("refresh-token", cookie, StringComparison.OrdinalIgnoreCase);

        var cookiePair = cookie.Split(';')[0];
        context.Request.Headers.Cookie = cookiePair;
        context.Request.Headers[WorkspaceSessionManager.CsrfHeaderName] = session!.CsrfToken;
        Assert.True(manager.HasValidCsrfToken(context.Request, session));
        context.Request.Headers[WorkspaceSessionManager.CsrfHeaderName] = "wrong-token";
        Assert.False(manager.HasValidCsrfToken(context.Request, session));
    }

    private static void AssertCredentialPlaceholder(JsonElement provider, string key, string settingName)
    {
        var value = provider.GetProperty(key).GetString();
        Assert.True(
            value?.StartsWith("REPLACE_WITH_", StringComparison.Ordinal) == true,
            $"{settingName} must use an explicit REPLACE_WITH_ placeholder.");
    }

    private static Dictionary<string, string> ParseQuery(string url) =>
        QueryHelpers.ParseQuery(new Uri(url).Query)
            .ToDictionary(pair => pair.Key, pair => pair.Value.ToString());

    private static OAuthProviderClient CreateProviderClient(HttpMessageHandler handler)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["App:PublicOrigin"] = "http://localhost:5223",
                ["App:FrontendOrigin"] = "http://localhost:4200",
                ["OAuth:Google:ClientId"] = "google-client-id",
                ["OAuth:Google:ClientSecret"] = "google-client-secret",
                ["OAuth:Github:ClientId"] = "github-client-id",
                ["OAuth:Github:ClientSecret"] = "github-client-secret",
                ["OAuth:Discord:ClientId"] = "discord-client-id",
                ["OAuth:Discord:ClientSecret"] = "discord-client-secret"
            })
            .Build();
        return new OAuthProviderClient(configuration, new StubHttpClientFactory(handler), TimeProvider.System);
    }

    private sealed class StubHttpClientFactory(HttpMessageHandler? handler = null) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler ?? new HttpClientHandler());
    }

    private sealed class JsonResponseHandler(HttpStatusCode statusCode, string content) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => Task.FromResult(new HttpResponseMessage(statusCode)
            {
                Content = new StringContent(content)
            });
    }

    private sealed class GithubProfileVersionHandler : HttpMessageHandler
    {
        public string? ApiVersion { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            ApiVersion = request.Headers.GetValues("X-GitHub-Api-Version").SingleOrDefault();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"id\":123,\"login\":\"creator\",\"name\":\"Creator\"}")
            });
        }
    }

    private sealed class TestWebHostEnvironment(string environmentName) : IWebHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "OAuth.Tests";
        public string WebRootPath { get; set; } = string.Empty;
        public string ContentRootPath { get; set; } = string.Empty;
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
