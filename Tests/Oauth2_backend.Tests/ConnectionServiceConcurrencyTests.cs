using System.Net;
using Microsoft.Extensions.Configuration;
using Xunit;

public sealed class ConnectionServiceConcurrencyTests
{
    [Fact]
    public async Task AParallelRefreshRetriesAfterATransientTokenRefreshFailure()
    {
        var now = DateTimeOffset.UtcNow;
        var handler = new TransientThenSuccessfulGithubTokenHandler();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["App:PublicOrigin"] = "http://localhost:5223",
                ["App:FrontendOrigin"] = "http://localhost:4200",
                ["OAuth:Github:ClientId"] = "github-client-id",
                ["OAuth:Github:ClientSecret"] = "github-client-secret"
            })
            .Build();
        var clock = TimeProvider.System;
        var service = new ConnectionService(
            new OAuthProviderClient(configuration, new FakeClientFactory(handler), clock),
            clock);
        var session = new WorkspaceSession("workspace-test-id", "csrf-test-token", now);
        session.Connections[ProviderId.Github] = new StoredProviderConnection
        {
            Provider = ProviderId.Github,
            AccessToken = "expired-access-token",
            RefreshToken = "single-use-refresh-token",
            AccessTokenExpiresAt = now.AddSeconds(-1),
            Profile = new ProviderProfile("Old profile", "creator", null, null, null),
            ConnectedAt = now.AddDays(-1)
        };

        var firstRefresh = service.RefreshProviderAsync(session, ProviderId.Github);
        await handler.FirstRefreshStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var queuedRefresh = service.RefreshProviderAsync(session, ProviderId.Github);
        handler.ReleaseFirstRefresh();
        await Task.WhenAll(firstRefresh, queuedRefresh);

        var connection = session.Connections[ProviderId.Github];
        Assert.Equal(2, handler.RefreshRequests);
        Assert.Equal(1, handler.ProfileRequests);
        Assert.Equal("connected", connection.Status);
        Assert.Equal("rotated-refresh-token", connection.RefreshToken);
        Assert.Equal("creator", connection.Profile?.Identifier);
    }

    [Fact]
    public async Task ReauthorizationDoesNotRestoreARefreshTokenRejectedByAnInFlightRefresh()
    {
        var now = DateTimeOffset.UtcNow;
        var handler = new ReauthorizationDuringGithubRefreshHandler();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["App:PublicOrigin"] = "http://localhost:5223",
                ["App:FrontendOrigin"] = "http://localhost:4200",
                ["OAuth:Github:ClientId"] = "github-client-id",
                ["OAuth:Github:ClientSecret"] = "github-client-secret"
            })
            .Build();
        var clock = TimeProvider.System;
        var service = new ConnectionService(
            new OAuthProviderClient(configuration, new FakeClientFactory(handler), clock),
            clock);
        var session = new WorkspaceSession("workspace-test-id", "csrf-test-token", now);
        session.Connections[ProviderId.Github] = new StoredProviderConnection
        {
            Provider = ProviderId.Github,
            AccessToken = "expired-access-token",
            RefreshToken = "refresh-token-rejected-by-provider",
            AccessTokenExpiresAt = now.AddSeconds(-1),
            Profile = new ProviderProfile("Creator", "creator", null, null, null) { AccountKey = "123" },
            ConnectedAt = now.AddDays(-1)
        };

        var inFlightRefresh = service.RefreshProviderAsync(session, ProviderId.Github);
        await handler.RefreshStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var reauthorization = service.CompleteAuthorizationAsync(
            session,
            ProviderId.Github,
            "authorization-code",
            new string('v', 43));
        await handler.CodeExchangeResponded.Task.WaitAsync(TimeSpan.FromSeconds(2));
        _ = await Task.WhenAny(
            handler.CallbackProfileStarted.Task,
            Task.Delay(TimeSpan.FromMilliseconds(100)));

        handler.ReleaseRefresh();
        handler.ReleaseCallbackProfile();
        await Task.WhenAll(inFlightRefresh, reauthorization);

        var connection = session.Connections[ProviderId.Github];
        Assert.Equal("connected", connection.Status);
        Assert.Equal("creator", connection.Profile?.Identifier);
        Assert.Null(connection.RefreshToken);
    }

    [Fact]
    public async Task ACallbackWaitingForRefreshCannotUndoDisconnect()
    {
        var now = DateTimeOffset.UtcNow;
        var handler = new ReauthorizationDuringGithubRefreshHandler();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["App:PublicOrigin"] = "http://localhost:5223",
                ["App:FrontendOrigin"] = "http://localhost:4200",
                ["OAuth:Github:ClientId"] = "github-client-id",
                ["OAuth:Github:ClientSecret"] = "github-client-secret"
            })
            .Build();
        var clock = TimeProvider.System;
        var service = new ConnectionService(
            new OAuthProviderClient(configuration, new FakeClientFactory(handler), clock),
            clock);
        var session = new WorkspaceSession("workspace-test-id", "csrf-test-token", now);
        session.Connections[ProviderId.Github] = new StoredProviderConnection
        {
            Provider = ProviderId.Github,
            AccessToken = "expired-access-token",
            RefreshToken = "single-use-refresh-token",
            AccessTokenExpiresAt = now.AddSeconds(-1),
            Profile = new ProviderProfile("Creator", "creator", null, null, null) { AccountKey = "123" },
            ConnectedAt = now.AddDays(-1)
        };

        var inFlightRefresh = service.RefreshProviderAsync(session, ProviderId.Github);
        await handler.RefreshStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var transactionGeneration = session.GetProviderGeneration(ProviderId.Github);
        var callback = service.CompleteAuthorizationAsync(
            session,
            ProviderId.Github,
            "authorization-code",
            new string('v', 43),
            transactionGeneration);
        await handler.CodeExchangeResponded.Task.WaitAsync(TimeSpan.FromSeconds(2));
        _ = await Task.WhenAny(
            handler.CallbackProfileStarted.Task,
            Task.Delay(TimeSpan.FromMilliseconds(100)));

        service.Disconnect(session, ProviderId.Github);
        handler.ReleaseRefresh();
        handler.ReleaseCallbackProfile();
        await inFlightRefresh;
        var error = await Assert.ThrowsAsync<ProviderRequestException>(() => callback);

        Assert.Equal("authorization_cancelled", error.Reason);
        Assert.False(session.Connections.ContainsKey(ProviderId.Github));
    }

    [Fact]
    public async Task ConcurrentGithubRefreshesUseAProviderTokenRotationOnlyOnce()
    {
        var now = DateTimeOffset.UtcNow;
        var handler = new RotatingGithubTokenHandler();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["App:PublicOrigin"] = "http://localhost:5223",
                ["App:FrontendOrigin"] = "http://localhost:4200",
                ["OAuth:Github:ClientId"] = "github-client-id",
                ["OAuth:Github:ClientSecret"] = "github-client-secret"
            })
            .Build();
        var clock = TimeProvider.System;
        var service = new ConnectionService(
            new OAuthProviderClient(configuration, new FakeClientFactory(handler), clock),
            clock);
        var session = new WorkspaceSession("workspace-test-id", "csrf-test-token", now);
        session.Connections[ProviderId.Github] = new StoredProviderConnection
        {
            Provider = ProviderId.Github,
            AccessToken = "expired-access-token",
            RefreshToken = "single-use-refresh-token",
            AccessTokenExpiresAt = now.AddSeconds(-1),
            Profile = new ProviderProfile("Old profile", "creator", null, null, null),
            ConnectedAt = now.AddDays(-1)
        };

        await Task.WhenAll(
            service.RefreshProviderAsync(session, ProviderId.Github),
            service.RefreshProviderAsync(session, ProviderId.Github));

        var connection = session.Connections[ProviderId.Github];
        Assert.Equal(1, handler.RefreshRequests);
        Assert.Equal(1, handler.ProfileRequests);
        Assert.Equal("connected", connection.Status);
        Assert.Equal("rotated-refresh-token", connection.RefreshToken);
        Assert.Equal("creator", connection.Profile?.Identifier);
    }

    private sealed class FakeClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class RotatingGithubTokenHandler : HttpMessageHandler
    {
        private readonly TaskCompletionSource _profileFetched = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int RefreshRequests;
        public int ProfileRequests;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.RequestUri?.Host == "github.com")
            {
                var number = Interlocked.Increment(ref RefreshRequests);
                if (number == 1)
                {
                    await Task.Delay(25, cancellationToken);
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(
                            "{\"access_token\":\"rotated-access-token\","
                            + "\"refresh_token\":\"rotated-refresh-token\","
                            + "\"expires_in\":28800,\"scope\":\"offline_access\"}")
                    };
                }

                await _profileFetched.Task.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken);
                return new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent("{\"error\":\"invalid_grant\"}")
                };
            }

            if (request.RequestUri?.Host == "api.github.com")
            {
                Interlocked.Increment(ref ProfileRequests);
                _profileFetched.TrySetResult();
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        "{\"id\":123,\"login\":\"creator\",\"name\":\"Creator\"}")
                };
            }

            throw new InvalidOperationException("Unexpected provider endpoint.");
        }
    }

    private sealed class TransientThenSuccessfulGithubTokenHandler : HttpMessageHandler
    {
        private readonly TaskCompletionSource _releaseFirstRefresh = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource FirstRefreshStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int RefreshRequests;
        public int ProfileRequests;

        public void ReleaseFirstRefresh() => _releaseFirstRefresh.TrySetResult();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.RequestUri?.Host == "github.com")
            {
                var number = Interlocked.Increment(ref RefreshRequests);
                if (number == 1)
                {
                    FirstRefreshStarted.TrySetResult();
                    await _releaseFirstRefresh.Task.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken);
                    return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
                }

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        "{\"access_token\":\"rotated-access-token\","
                        + "\"refresh_token\":\"rotated-refresh-token\","
                        + "\"expires_in\":28800,\"scope\":\"offline_access\"}")
                };
            }

            if (request.RequestUri?.Host == "api.github.com")
            {
                Interlocked.Increment(ref ProfileRequests);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        "{\"id\":123,\"login\":\"creator\",\"name\":\"Creator\"}")
                };
            }

            throw new InvalidOperationException("Unexpected provider endpoint.");
        }
    }

    private sealed class ReauthorizationDuringGithubRefreshHandler : HttpMessageHandler
    {
        private readonly TaskCompletionSource _releaseRefresh = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseCallbackProfile = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource RefreshStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource CodeExchangeResponded { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource CallbackProfileStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void ReleaseRefresh() => _releaseRefresh.TrySetResult();
        public void ReleaseCallbackProfile() => _releaseCallbackProfile.TrySetResult();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.RequestUri?.Host == "github.com")
            {
                var form = await request.Content!.ReadAsStringAsync(cancellationToken);
                if (form.Contains("grant_type=refresh_token", StringComparison.Ordinal))
                {
                    RefreshStarted.TrySetResult();
                    await _releaseRefresh.Task.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken);
                    return new HttpResponseMessage(HttpStatusCode.BadRequest)
                    {
                        Content = new StringContent("{\"error\":\"invalid_grant\"}")
                    };
                }

                CodeExchangeResponded.TrySetResult();
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        "{\"access_token\":\"reauthorized-access-token\","
                        + "\"scope\":\"offline_access\"}")
                };
            }

            if (request.RequestUri?.Host == "api.github.com")
            {
                CallbackProfileStarted.TrySetResult();
                await _releaseCallbackProfile.Task.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        "{\"id\":123,\"login\":\"creator\",\"name\":\"Creator\"}")
                };
            }

            throw new InvalidOperationException("Unexpected provider endpoint.");
        }
    }
}
