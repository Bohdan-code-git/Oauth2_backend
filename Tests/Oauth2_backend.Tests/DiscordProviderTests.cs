using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.WebUtilities;
using Xunit;

public sealed class DiscordProviderTests
{
    [Fact]
    public void PublicProviderContractListsDiscordWithItsDocumentedWebFlow()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["App:PublicOrigin"] = "http://localhost:5223",
                ["App:FrontendOrigin"] = "http://localhost:4300",
                ["OAuth:Discord:ClientId"] = "discord-client-id",
                ["OAuth:Discord:ClientSecret"] = "discord-client-secret"
            })
            .Build();
        var client = new OAuthProviderClient(configuration, new StubHttpClientFactory(new HttpClientHandler()), TimeProvider.System);

        var providers = client.GetPublicProviderConfiguration().Providers;

        Assert.Equal(["google", "github", "discord"], providers.Select(provider => provider.Provider));
        var discord = Assert.Single(providers, provider => provider.Provider == "discord");
        Assert.Equal("Discord", discord.Label);
        Assert.True(discord.Configured);
        Assert.Equal("https://discord.com/oauth2/authorize", discord.AuthorizationEndpoint);
        Assert.Equal("https://discord.com/api/oauth2/token", discord.TokenEndpoint);
        Assert.Equal("http://localhost:5223/api/oauth/discord/callback", discord.CallbackUri);
        Assert.Equal(["identify"], discord.Scopes);
        Assert.Null(discord.PkceMethod);
    }

    [Fact]
    public async Task AuthorizationCodeExchangeUsesDiscordFormContractWithoutPkceVerifier()
    {
        var handler = new DiscordTokenHandler();
        var client = CreateClient(handler);

        var token = await client.ExchangeCodeAsync(ProviderId.Discord, "code-from-discord", null);

        Assert.True(handler.FormObserved);
        Assert.Equal("code-from-discord", handler.Form["code"]);
        Assert.Equal("authorization_code", handler.Form["grant_type"]);
        Assert.Equal("http://localhost:5223/api/oauth/discord/callback", handler.Form["redirect_uri"]);
        Assert.Equal("discord-client-id", handler.Form["client_id"]);
        Assert.Equal("discord-client-secret", handler.Form["client_secret"]);
        Assert.DoesNotContain("code_verifier", handler.Form.Keys, StringComparer.Ordinal);
        Assert.Equal("identify", Assert.Single(token.GrantedScopes!));
        Assert.Equal("discord-refresh-token-test", token.RefreshToken);
        Assert.True(token.ExpiresAt > TimeProvider.System.GetUtcNow());
    }

    [Fact]
    public async Task RefreshExchangeUsesDiscordFormContractAndAcceptsRotatedRefreshToken()
    {
        var handler = new DiscordRefreshTokenHandler();
        var client = CreateClient(handler);

        var token = await client.RefreshAsync(ProviderId.Discord, "discord-old-refresh-token");

        Assert.Equal("refresh_token", handler.Form["grant_type"]);
        Assert.Equal("discord-old-refresh-token", handler.Form["refresh_token"]);
        Assert.Equal("discord-client-id", handler.Form["client_id"]);
        Assert.Equal("discord-client-secret", handler.Form["client_secret"]);
        Assert.DoesNotContain("code", handler.Form.Keys, StringComparer.Ordinal);
        Assert.DoesNotContain("code_verifier", handler.Form.Keys, StringComparer.Ordinal);
        Assert.Equal("discord-new-refresh-token", token.RefreshToken);
        Assert.Equal("discord-new-access-token", token.AccessToken);
    }

    [Fact]
    public async Task CurrentUserProfileUsesBearerTokenAndKeepsSnowflakeAsPrivateAccountKey()
    {
        var handler = new DiscordProfileHandler();
        var client = CreateClient(handler);

        var profile = await client.GetProfileAsync(ProviderId.Discord, "discord-access-token-test");

        Assert.Equal(HttpMethod.Get, handler.Method);
        Assert.Equal("/api/v10/users/@me", handler.Path);
        Assert.Equal("Bearer", handler.AuthorizationScheme);
        Assert.Equal("discord-access-token-test", handler.AuthorizationParameter);
        Assert.Equal("Mira Dev", profile?.DisplayName);
        Assert.Equal("mira.dev", profile?.Identifier);
        Assert.Null(profile?.Email);
        Assert.Equal("https://cdn.discordapp.com/avatars/4815162342/a_avatarhash.gif", profile?.AvatarUrl);
        Assert.Equal("https://discord.com/users/4815162342", profile?.ProfileUrl);
        Assert.Equal("4815162342", profile?.AccountKey);

        var publicJson = JsonSerializer.Serialize(profile);
        Assert.DoesNotContain("accountKey", publicJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("discord-access-token-test", publicJson, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DiscordProfileRejectsResponsesWithoutStableUserId()
    {
        var client = CreateClient(new JsonHandler("{\"username\":\"mira.dev\"}"));

        var error = await Assert.ThrowsAsync<ProviderRequestException>(() =>
            client.GetProfileAsync(ProviderId.Discord, "discord-access-token-test"));

        Assert.Equal("invalid_provider_profile", error.Reason);
    }

    private static OAuthProviderClient CreateClient(HttpMessageHandler handler)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["App:PublicOrigin"] = "http://localhost:5223",
                ["App:FrontendOrigin"] = "http://localhost:4300",
                ["OAuth:Discord:ClientId"] = "discord-client-id",
                ["OAuth:Discord:ClientSecret"] = "discord-client-secret"
            })
            .Build();
        return new OAuthProviderClient(configuration, new StubHttpClientFactory(handler), TimeProvider.System);
    }

    private sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class DiscordTokenHandler : HttpMessageHandler
    {
        public bool FormObserved { get; private set; }
        public Dictionary<string, string> Form { get; private set; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Assert.Equal("https://discord.com/api/oauth2/token", request.RequestUri?.ToString());
            Assert.Equal("application/x-www-form-urlencoded", request.Content?.Headers.ContentType?.MediaType);
            Form = QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(cancellationToken))
                .ToDictionary(pair => pair.Key, pair => pair.Value.ToString());
            FormObserved = true;
            return Json("{\"access_token\":\"discord-access-token-test\","
                + "\"refresh_token\":\"discord-refresh-token-test\",\"expires_in\":604800,"
                + "\"scope\":\"identify\"}");
        }
    }

    private sealed class DiscordProfileHandler : HttpMessageHandler
    {
        public HttpMethod? Method { get; private set; }
        public string? Path { get; private set; }
        public string? AuthorizationScheme { get; private set; }
        public string? AuthorizationParameter { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Method = request.Method;
            Path = request.RequestUri?.PathAndQuery;
            AuthorizationScheme = request.Headers.Authorization?.Scheme;
            AuthorizationParameter = request.Headers.Authorization?.Parameter;
            return Task.FromResult(Json(
                "{\"id\":\"4815162342\",\"username\":\"mira.dev\","
                + "\"global_name\":\"Mira Dev\",\"avatar\":\"a_avatarhash\"}"));
        }
    }

    private sealed class DiscordRefreshTokenHandler : HttpMessageHandler
    {
        public Dictionary<string, string> Form { get; private set; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Assert.Equal("https://discord.com/api/oauth2/token", request.RequestUri?.ToString());
            Assert.Equal("application/x-www-form-urlencoded", request.Content?.Headers.ContentType?.MediaType);
            Form = QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(cancellationToken))
                .ToDictionary(pair => pair.Key, pair => pair.Value.ToString());
            return Json("{\"access_token\":\"discord-new-access-token\","
                + "\"refresh_token\":\"discord-new-refresh-token\",\"expires_in\":604800,"
                + "\"scope\":\"identify\"}");
        }
    }

    private sealed class JsonHandler(string content) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => Task.FromResult(Json(content));
    }

    private static HttpResponseMessage Json(string content) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(content, new MediaTypeHeaderValue("application/json"))
    };
}
