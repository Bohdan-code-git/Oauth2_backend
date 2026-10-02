using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Xunit;

public sealed class ConnectionServiceAuthorizationTests
{
    [Fact]
    public async Task GoogleAuthorizationWithoutRefreshTokenRequiresReauthorizationAfterProfileFetch()
    {
        var now = DateTimeOffset.UtcNow;
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["App:PublicOrigin"] = "http://localhost:5223",
                ["App:FrontendOrigin"] = "http://localhost:4200",
                ["OAuth:Google:ClientId"] = "google-client-id",
                ["OAuth:Google:ClientSecret"] = "google-client-secret"
            })
            .Build();
        var service = new ConnectionService(
            new OAuthProviderClient(configuration, new FakeClientFactory(new GoogleTokenWithoutRefreshHandler()), TimeProvider.System),
            TimeProvider.System);
        var session = new WorkspaceSession("workspace-test-id", "csrf-test-token", now);

        var snapshot = await service.CompleteAuthorizationAsync(
            session,
            ProviderId.Google,
            "new-authorization-code",
            new string('v', 43));

        var connection = Assert.Single(snapshot.Connections, item => item.Provider == "google");
        Assert.Equal("reauth_required", connection.Status);
        Assert.Equal("Creator", connection.Profile?.DisplayName);
        Assert.Contains("refresh token", connection.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(session.Connections[ProviderId.Google].RefreshToken);
        Assert.NotNull(session.Connections[ProviderId.Google].AccessTokenExpiresAt);
        Assert.False(connection.CanRefreshAccessToken);
        Assert.Equal(new[] { "email", "openid", "profile" }, connection.GrantedScopes);
    }

    [Fact]
    public async Task ReauthorizingAsAnotherGithubAccountDoesNotReuseThePreviousRefreshToken()
    {
        var connection = await ReauthorizeGithubAsync("account-a", "account-b");

        Assert.Equal("account-b", connection.Profile?.Identifier);
        Assert.Null(connection.RefreshToken);
    }

    [Fact]
    public async Task ReauthorizingTheSameGithubAccountKeepsItsExistingRefreshTokenWhenOmitted()
    {
        var connection = await ReauthorizeGithubAsync("same-account", "same-account");

        Assert.Equal("same-account", connection.Profile?.Identifier);
        Assert.Equal("existing-refresh-token", connection.RefreshToken);
    }

    [Theory]
    [InlineData("same-account", "existing-refresh-token")]
    [InlineData("new-account", null)]
    public async Task PreviousRefreshTokenIsKeptServerSideUntilRetryVerifiesTheAccount(
        string authorizedAccount,
        string? expectedRefreshToken)
    {
        var now = DateTimeOffset.UtcNow;
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["App:PublicOrigin"] = "http://localhost:5223",
                ["App:FrontendOrigin"] = "http://localhost:4200",
                ["OAuth:Github:ClientId"] = "github-client-id",
                ["OAuth:Github:ClientSecret"] = "github-client-secret"
            })
            .Build();
        var service = new ConnectionService(
            new OAuthProviderClient(
                configuration,
                new FakeClientFactory(new TransientProfileFailureHandler(authorizedAccount)),
                TimeProvider.System),
            TimeProvider.System);
        var session = new WorkspaceSession("workspace-test-id", "csrf-test-token", now);
        session.Connections[ProviderId.Github] = new StoredProviderConnection
        {
            Provider = ProviderId.Github,
            AccessToken = "old-access-token",
            RefreshToken = "existing-refresh-token",
            Profile = new ProviderProfile("Previous profile", "same-account", null, null, null)
            {
                AccountKey = "provider-id-same-account"
            },
            ConnectedAt = now.AddDays(-1)
        };

        _ = await service.CompleteAuthorizationAsync(
            session,
            ProviderId.Github,
            "new-authorization-code",
            new string('v', 43));

        var pending = session.Connections[ProviderId.Github];
        Assert.Null(pending.Profile);
        Assert.Null(pending.RefreshToken);
        Assert.Equal("existing-refresh-token", pending.PreviousConnection?.RefreshToken);

        _ = await service.RefreshProviderAsync(session, ProviderId.Github);

        var completed = session.Connections[ProviderId.Github];
        Assert.Equal(authorizedAccount, completed.Profile?.Identifier);
        Assert.Equal(expectedRefreshToken, completed.RefreshToken);
        Assert.Null(completed.PreviousConnection);
        if (authorizedAccount == "same-account")
            Assert.Equal(now.AddDays(-1), completed.ConnectedAt);
        else
            Assert.NotEqual(now.AddDays(-1), completed.ConnectedAt);
    }

    private static async Task<StoredProviderConnection> ReauthorizeGithubAsync(
        string oldIdentifier,
        string newIdentifier)
    {
        var now = DateTimeOffset.UtcNow;
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["App:PublicOrigin"] = "http://localhost:5223",
                ["App:FrontendOrigin"] = "http://localhost:4200",
                ["OAuth:Github:ClientId"] = "github-client-id",
                ["OAuth:Github:ClientSecret"] = "github-client-secret"
            })
            .Build();
        var providers = new OAuthProviderClient(
            configuration,
            new FakeClientFactory(new ReauthorizationHandler(newIdentifier)),
            TimeProvider.System);
        var service = new ConnectionService(
            providers,
            TimeProvider.System);
        var session = new WorkspaceSession("workspace-test-id", "csrf-test-token", now);
        session.Connections[ProviderId.Github] = new StoredProviderConnection
        {
            Provider = ProviderId.Github,
            AccessToken = "old-access-token",
            RefreshToken = "existing-refresh-token",
            Profile = new ProviderProfile("Previous profile", oldIdentifier, null, null, null)
            {
                AccountKey = "provider-id-" + oldIdentifier
            },
            ConnectedAt = now.AddDays(-1)
        };

        _ = await service.CompleteAuthorizationAsync(
            session,
            ProviderId.Github,
            "new-authorization-code",
            new string('v', 43));

        return session.Connections[ProviderId.Github];
    }

    private sealed class FakeClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class ReauthorizationHandler(string newIdentifier) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var body = request.RequestUri?.Host == "github.com"
                ? "{\"access_token\":\"new-access-token\",\"expires_in\":28800,\"scope\":\"\"}"
                : "{\"id\":\"provider-id-" + newIdentifier
                    + "\",\"login\":\"" + newIdentifier + "\",\"name\":\"New profile\"}";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body)
            });
        }
    }

    private sealed class TransientProfileFailureHandler(string authorizedAccount) : HttpMessageHandler
    {
        private int _profileRequests;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.RequestUri?.Host == "github.com")
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        "{\"access_token\":\"new-access-token\",\"expires_in\":28800,\"scope\":\"\"}")
                });
            }

            if (Interlocked.Increment(ref _profileRequests) == 1)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "{\"id\":\"provider-id-" + authorizedAccount
                    + "\",\"login\":\"" + authorizedAccount + "\",\"name\":\"New profile\"}")
            });
        }
    }

    private sealed class GoogleTokenWithoutRefreshHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var body = request.RequestUri?.Host switch
            {
                "oauth2.googleapis.com" => "{\"access_token\":\"google-access-token-test-only\","
                    + "\"scope\":\"openid email profile\",\"expires_in\":3600}",
                "openidconnect.googleapis.com" => "{\"sub\":\"google-subject-test-only\","
                    + "\"email\":\"creator@example.test\",\"email_verified\":true,\"name\":\"Creator\"}",
                _ => throw new InvalidOperationException("Unexpected provider endpoint.")
            };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body)
            });
        }
    }
}
