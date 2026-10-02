using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.AspNetCore.WebUtilities;
using Xunit;

public sealed class OAuthControllerFlowTests
{
    [Fact]
    public async Task ProviderStartRequiresWorkspaceCsrfAndCallbacksStayInTheStartingBrowser()
    {
        var handler = new CountingProviderTransportHandler();
        var fixture = new OAuthFixture(handler);
        var browserAStart = new DefaultHttpContext();
        var browserA = StartProvider(fixture, browserAStart, "github");
        var state = QueryHelpers.ParseQuery(new Uri(browserA.Url!).Query)["state"].ToString();
        var browserACookie = browserAStart.Request.Headers.Cookie.ToString();

        var deniedStart = new DefaultHttpContext();
        deniedStart.Request.Headers.Cookie = browserACookie;
        var denied = fixture.CreateController(deniedStart).Start("google");
        Assert.Contains("reason=csrf_validation_failed", Assert.IsType<RedirectResult>(denied).Url, StringComparison.Ordinal);

        var browserBStart = new DefaultHttpContext();
        _ = StartProvider(fixture, browserBStart, "github");
        var browserBCookie = browserBStart.Request.Headers.Cookie.ToString();
        Assert.NotEqual(browserACookie, browserBCookie);

        var callback = new DefaultHttpContext();
        callback.Request.Headers.Cookie = browserBCookie;
        callback.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["state"] = state,
            ["code"] = "authorization-code"
        });
        var result = await fixture.CreateController(callback).Callback("github", CancellationToken.None);

        Assert.Contains("reason=state_mismatch", Assert.IsType<RedirectResult>(result).Url, StringComparison.Ordinal);
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public void ProviderStartWithoutAnExistingWorkspaceRejectsCsrfWithoutIssuingAReplacementCookie()
    {
        var fixture = new OAuthFixture(new CountingProviderTransportHandler());
        var context = new DefaultHttpContext();

        var result = fixture.CreateController(context).Start("discord", "attacker-supplied-value");

        Assert.Contains("reason=session_expired", Assert.IsType<RedirectResult>(result).Url, StringComparison.Ordinal);
        Assert.Equal(0, context.Response.Headers.SetCookie.Count);
    }

    [Fact]
    public void DemoModePreservesExistingProviderProfilesInsteadOfReplacingThemWithPlaceholders()
    {
        var fixture = new OAuthFixture(new FakeGithubHandler("unused-token"), forceDemo: true);
        var now = TimeProvider.System.GetUtcNow();
        var session = new WorkspaceSession("workspace-id", "csrf-token", now);
        session.Connections[ProviderId.Github] = new StoredProviderConnection
        {
            Provider = ProviderId.Github,
            AccessToken = "private-access-token-sentinel",
            RefreshToken = "private-refresh-token-sentinel",
            ConnectedAt = now.AddMinutes(-15),
            LastSyncedAt = now.AddMinutes(-5),
            Profile = new ProviderProfile("Saved GitHub account", "creator", null, null, null)
        };

        var response = fixture.Connections.GetSnapshot(session);
        var github = Assert.Single(response.Connections, connection => connection.Provider == "github");

        Assert.True(response.DemoMode);
        Assert.Equal("connected", github.Status);
        Assert.Equal("Saved GitHub account", github.Profile?.DisplayName);
        Assert.Equal(now.AddMinutes(-5), github.LastSyncedAt);
        var publicJson = JsonSerializer.Serialize(response);
        Assert.DoesNotContain("private-access-token-sentinel", publicJson, StringComparison.Ordinal);
        Assert.DoesNotContain("private-refresh-token-sentinel", publicJson, StringComparison.Ordinal);
    }

    [Fact]
    public void DemoModeRejectsProviderDisconnectWithoutDeletingTheSavedConnection()
    {
        var fixture = new OAuthFixture(new FakeGithubHandler("unused-token"), forceDemo: true);
        var now = TimeProvider.System.GetUtcNow();
        var session = fixture.Store.GetOrCreate(null);
        var savedConnection = new StoredProviderConnection
        {
            Provider = ProviderId.Github,
            AccessToken = "private-access-token-sentinel",
            RefreshToken = "private-refresh-token-sentinel",
            ConnectedAt = now.AddMinutes(-15),
            LastSyncedAt = now.AddMinutes(-5),
            Profile = new ProviderProfile("Saved GitHub account", "creator", null, null, null)
        };
        session.Connections[ProviderId.Github] = savedConnection;
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"switchboard.sid={session.Id}";
        context.Request.Headers[WorkspaceSessionManager.CsrfHeaderName] = session.CsrfToken;

        var result = fixture.CreateConnectionsController(context).Disconnect("github");

        var conflict = Assert.IsType<ConflictObjectResult>(result);
        Assert.Equal(StatusCodes.Status409Conflict, conflict.StatusCode);
        Assert.True(session.Connections.TryGetValue(ProviderId.Github, out var preserved));
        Assert.Same(savedConnection, preserved);
    }

    [Fact]
    public void AnonymousWorkspaceClearRequiresCsrfAndDeletesOnlyTheDemoWorkspaceCookie()
    {
        var fixture = new OAuthFixture(new FakeGithubHandler("unused-token"));
        var bootstrapContext = new DefaultHttpContext();
        var sessionController = fixture.CreateSessionController(bootstrapContext);
        var bootstrap = Assert.IsType<OkObjectResult>(sessionController.Get().Result);
        var session = Assert.IsType<SessionResponse>(bootstrap.Value);
        Assert.Equal("browser_workspace", session.AccessMode);
        var sessionJson = JsonSerializer.Serialize(session);
        Assert.DoesNotContain("user", sessionJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("access_token", sessionJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("id_token", sessionJson, StringComparison.OrdinalIgnoreCase);
        var cookie = bootstrapContext.Response.Headers.SetCookie.ToString().Split(';')[0];
        var sessionId = cookie[(cookie.IndexOf('=') + 1)..];
        Assert.NotNull(fixture.Store.Find(sessionId));

        var rejectedContext = new DefaultHttpContext();
        rejectedContext.Request.Headers.Cookie = cookie;
        rejectedContext.Request.Headers[WorkspaceSessionManager.CsrfHeaderName] = "wrong-token";
        var rejected = fixture.CreateSessionController(rejectedContext).ClearWorkspace();

        var forbidden = Assert.IsType<ObjectResult>(rejected);
        Assert.Equal(StatusCodes.Status403Forbidden, forbidden.StatusCode);
        Assert.NotNull(fixture.Store.Find(sessionId));
        Assert.Equal(0, rejectedContext.Response.Headers.SetCookie.Count);

        var logoutContext = new DefaultHttpContext();
        logoutContext.Request.Headers.Cookie = cookie;
        logoutContext.Request.Headers[WorkspaceSessionManager.CsrfHeaderName] = session.CsrfToken;
        var result = fixture.CreateSessionController(logoutContext).ClearWorkspace();

        Assert.IsType<NoContentResult>(result);
        Assert.Null(fixture.Store.Find(sessionId));
        var clearedCookie = logoutContext.Response.Headers.SetCookie.ToString();
        Assert.Contains("switchboard.sid=;", clearedCookie, StringComparison.Ordinal);
        Assert.Contains("expires=", clearedCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", clearedCookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AnonymousWorkspaceClearWithoutCsrfRejectsAndPreservesTheWorkspace()
    {
        var fixture = new OAuthFixture(new FakeGithubHandler("unused-token"));
        var bootstrapContext = new DefaultHttpContext();
        var bootstrap = Assert.IsType<OkObjectResult>(fixture.CreateSessionController(bootstrapContext).Get().Result);
        var cookie = bootstrapContext.Response.Headers.SetCookie.ToString().Split(';')[0];
        var sessionId = cookie[(cookie.IndexOf('=') + 1)..];

        var logoutContext = new DefaultHttpContext();
        logoutContext.Request.Headers.Cookie = cookie;
        var result = fixture.CreateSessionController(logoutContext).ClearWorkspace();

        var forbidden = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, forbidden.StatusCode);
        Assert.NotNull(fixture.Store.Find(sessionId));
        Assert.Equal(0, logoutContext.Response.Headers.SetCookie.Count);
    }

    [Fact]
    public void ProductionWorkspaceClearDeletesHostCookieWithSecureScopeAndExpiredLifetime()
    {
        var fixture = new OAuthFixture(
            new FakeGithubHandler("unused-token"),
            environmentName: "Production");
        var bootstrapContext = new DefaultHttpContext();
        var bootstrap = Assert.IsType<OkObjectResult>(fixture.CreateSessionController(bootstrapContext).Get().Result);
        var session = Assert.IsType<SessionResponse>(bootstrap.Value);
        var cookie = bootstrapContext.Response.Headers.SetCookie.ToString().Split(';')[0];
        var sessionId = cookie[(cookie.IndexOf('=') + 1)..];
        Assert.StartsWith("__Host-switchboard.sid=", cookie, StringComparison.Ordinal);

        var logoutContext = new DefaultHttpContext();
        logoutContext.Request.Headers.Cookie = cookie;
        logoutContext.Request.Headers[WorkspaceSessionManager.CsrfHeaderName] = session.CsrfToken;
        var result = fixture.CreateSessionController(logoutContext).ClearWorkspace();

        Assert.IsType<NoContentResult>(result);
        Assert.Null(fixture.Store.Find(sessionId));
        var clearedCookie = logoutContext.Response.Headers.SetCookie.ToString();
        Assert.Contains("__Host-switchboard.sid=;", clearedCookie, StringComparison.Ordinal);
        Assert.Contains("expires=Thu, 01 Jan 1970 00:00:00 GMT", clearedCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", clearedCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", clearedCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", clearedCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", clearedCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("domain=", clearedCookie, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("bulk-refresh", false)]
    [InlineData("bulk-refresh", true)]
    [InlineData("provider-refresh", false)]
    [InlineData("provider-refresh", true)]
    [InlineData("disconnect", false)]
    [InlineData("disconnect", true)]
    public async Task ConnectionMutationsRejectMissingOrWrongCsrfBeforeChangingStateOrCallingProviders(
        string operation,
        bool sendWrongCsrf)
    {
        var handler = new FakeGithubHandler("github-handler-token");
        var fixture = new OAuthFixture(handler);
        var now = TimeProvider.System.GetUtcNow();
        var session = fixture.Store.GetOrCreate(null);
        var connection = new StoredProviderConnection
        {
            Provider = ProviderId.Github,
            AccessToken = "github-handler-token",
            RefreshToken = "github-refresh-token",
            AccessTokenExpiresAt = now.AddHours(1),
            ConnectedAt = now.AddMinutes(-15),
            LastSyncedAt = now.AddMinutes(-5),
            Profile = new ProviderProfile("Saved GitHub account", "creator", null, null, null)
        };
        session.Connections[ProviderId.Github] = connection;

        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"switchboard.sid={session.Id}";
        if (sendWrongCsrf)
            context.Request.Headers[WorkspaceSessionManager.CsrfHeaderName] = "wrong-csrf-token";

        var controller = fixture.CreateConnectionsController(context);
        int statusCode;
        switch (operation)
        {
            case "bulk-refresh":
                var bulkRefresh = await controller.Refresh(CancellationToken.None);
                statusCode = Assert.IsType<ObjectResult>(bulkRefresh.Result).StatusCode!.Value;
                break;
            case "provider-refresh":
                var providerRefresh = await controller.RefreshProvider("github", CancellationToken.None);
                statusCode = Assert.IsType<ObjectResult>(providerRefresh.Result).StatusCode!.Value;
                break;
            case "disconnect":
                statusCode = Assert.IsType<ObjectResult>(controller.Disconnect("github")).StatusCode!.Value;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(operation), operation, "Unknown test operation.");
        }

        Assert.Equal(StatusCodes.Status403Forbidden, statusCode);
        Assert.Equal(0, handler.RequestCount);
        Assert.True(session.Connections.TryGetValue(ProviderId.Github, out var preserved));
        Assert.Same(connection, preserved);
        Assert.Equal("connected", connection.Status);
        Assert.Equal(now.AddMinutes(-5), connection.LastSyncedAt);
    }

    [Fact]
    public async Task ForcedDemoRefreshesDoNotCallProvidersOrChangeSavedConnectionState()
    {
        var handler = new CountingProviderTransportHandler();
        var fixture = new OAuthFixture(handler, forceDemo: true);
        var now = TimeProvider.System.GetUtcNow();
        var session = fixture.Store.GetOrCreate(null);
        var profile = new ProviderProfile("Saved GitHub account", "creator", null, null, null);
        var connection = new StoredProviderConnection
        {
            Provider = ProviderId.Github,
            AccessToken = "private-access-token-sentinel",
            RefreshToken = "private-refresh-token-sentinel",
            AccessTokenExpiresAt = now.AddHours(1),
            ConnectedAt = now.AddMinutes(-15),
            LastSyncedAt = now.AddMinutes(-5),
            Profile = profile
        };
        session.Connections[ProviderId.Github] = connection;

        var bulkContext = CreateCsrfContext(session);
        var bulkRefresh = await fixture.CreateConnectionsController(bulkContext).Refresh(CancellationToken.None);
        var bulkResponse = Assert.IsType<ConnectionsResponse>(Assert.IsType<OkObjectResult>(bulkRefresh.Result).Value);

        var providerContext = CreateCsrfContext(session);
        var providerRefresh = await fixture.CreateConnectionsController(providerContext)
            .RefreshProvider("github", CancellationToken.None);
        var providerResponse = Assert.IsType<ConnectionsResponse>(Assert.IsType<OkObjectResult>(providerRefresh.Result).Value);

        Assert.True(bulkResponse.DemoMode);
        Assert.True(providerResponse.DemoMode);
        Assert.Equal(0, handler.RequestCount);
        Assert.True(session.Connections.TryGetValue(ProviderId.Github, out var preserved));
        Assert.Same(connection, preserved);
        Assert.Equal("private-access-token-sentinel", connection.AccessToken);
        Assert.Equal("private-refresh-token-sentinel", connection.RefreshToken);
        Assert.Equal("connected", connection.Status);
        Assert.Same(profile, connection.Profile);
        Assert.Equal(now.AddMinutes(-5), connection.LastSyncedAt);
        Assert.Equal(0, connection.SyncVersion);
    }

    private static DefaultHttpContext CreateCsrfContext(WorkspaceSession session)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"switchboard.sid={session.Id}";
        context.Request.Headers[WorkspaceSessionManager.CsrfHeaderName] = session.CsrfToken;
        return context;
    }

    private static RedirectResult StartProvider(OAuthFixture fixture, DefaultHttpContext context, string provider)
    {
        var bootstrap = fixture.CreateSessionController(context).Get();
        var session = Assert.IsType<SessionResponse>(Assert.IsType<OkObjectResult>(bootstrap.Result).Value);
        if (string.IsNullOrWhiteSpace(context.Request.Headers.Cookie))
        {
            var cookie = context.Response.Headers.SetCookie.ToString().Split(';')[0];
            context.Request.Headers.Cookie = cookie;
        }
        return Assert.IsType<RedirectResult>(fixture.CreateController(context).Start(provider, session.CsrfToken));
    }

    [Fact]
    public async Task GithubDeniedConsentCallbackMapsErrorWithoutExchangingCode()
    {
        var handler = new FakeGithubHandler("unused-token");
        var fixture = new OAuthFixture(handler);
        var startContext = new DefaultHttpContext();
        var start = StartProvider(fixture, startContext, "github");
        var parameters = QueryHelpers.ParseQuery(new Uri(start.Url!).Query);
        var cookie = startContext.Response.Headers.SetCookie.ToString().Split(';')[0];

        var callbackContext = new DefaultHttpContext();
        callbackContext.Request.Headers.Cookie = cookie;
        callbackContext.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["state"] = parameters["state"].ToString(),
            ["error"] = "access_denied"
        });
        var callback = await fixture.CreateController(callbackContext)
            .Callback("github", CancellationToken.None);

        var redirect = Assert.IsType<RedirectResult>(callback);
        Assert.Contains("oauth=error", redirect.Url, StringComparison.Ordinal);
        Assert.Contains("reason=access_denied", redirect.Url, StringComparison.Ordinal);
        Assert.DoesNotContain("short-lived-authorization-code", redirect.Url, StringComparison.Ordinal);
        Assert.Equal(0, handler.RequestCount);

        var resultContext = new DefaultHttpContext();
        resultContext.Request.Headers.Cookie = cookie;
        var result = fixture.CreateConnectionsController(resultContext).Get();
        var response = Assert.IsType<ConnectionsResponse>(Assert.IsType<OkObjectResult>(result.Result).Value);
        Assert.Equal(new OAuthFeedbackDto("github", "access_denied"), Assert.Single(response.OAuthFeedback!));

        var repeatedContext = new DefaultHttpContext();
        repeatedContext.Request.Headers.Cookie = cookie;
        var repeated = fixture.CreateConnectionsController(repeatedContext).Get();
        var repeatedResponse = Assert.IsType<ConnectionsResponse>(Assert.IsType<OkObjectResult>(repeated.Result).Value);
        Assert.Empty(repeatedResponse.OAuthFeedback!);
    }

    [Fact]
    public async Task ConcurrentDeniedCallbacksKeepBothProviderResultsUntilTheWorkspaceLoadsThem()
    {
        var handler = new FakeGithubHandler("unused-token");
        var fixture = new OAuthFixture(handler);
        var githubStartContext = new DefaultHttpContext();
        var githubStart = StartProvider(fixture, githubStartContext, "github");
        var cookie = githubStartContext.Response.Headers.SetCookie.ToString().Split(';')[0];
        var githubState = QueryHelpers.ParseQuery(new Uri(githubStart.Url!).Query)["state"].ToString();

        var googleStartContext = new DefaultHttpContext();
        googleStartContext.Request.Headers.Cookie = cookie;
        var googleStart = StartProvider(fixture, googleStartContext, "google");
        var googleState = QueryHelpers.ParseQuery(new Uri(googleStart.Url!).Query)["state"].ToString();

        foreach (var (provider, state) in new[] { ("github", githubState), ("google", googleState) })
        {
            var callbackContext = new DefaultHttpContext();
            callbackContext.Request.Headers.Cookie = cookie;
            callbackContext.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
            {
                ["state"] = state,
                ["error"] = "access_denied"
            });
            await fixture.CreateController(callbackContext).Callback(provider, CancellationToken.None);
        }

        var resultContext = new DefaultHttpContext();
        resultContext.Request.Headers.Cookie = cookie;
        var get = fixture.CreateConnectionsController(resultContext).Get();
        var response = Assert.IsType<ConnectionsResponse>(Assert.IsType<OkObjectResult>(get.Result).Value);
        Assert.Equal(2, response.OAuthFeedback?.Count);
        Assert.Contains(response.OAuthFeedback!, item => item.Provider == "github" && item.Reason == "access_denied");
        Assert.Contains(response.OAuthFeedback!, item => item.Provider == "google" && item.Reason == "access_denied");
    }

    [Fact]
    public async Task ProviderTimeoutIsReturnedAsOneSafeWorkspaceFeedback()
    {
        var fixture = new OAuthFixture(new TimeoutGithubHandler());
        var startContext = new DefaultHttpContext();
        var start = StartProvider(fixture, startContext, "github");
        var cookie = startContext.Response.Headers.SetCookie.ToString().Split(';')[0];
        var state = QueryHelpers.ParseQuery(new Uri(start.Url!).Query)["state"].ToString();

        var callbackContext = new DefaultHttpContext();
        callbackContext.Request.Headers.Cookie = cookie;
        callbackContext.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["state"] = state,
            ["code"] = "short-lived-authorization-code"
        });
        var callback = await fixture.CreateController(callbackContext).Callback("github", CancellationToken.None);
        Assert.Contains("reason=provider_timeout", Assert.IsType<RedirectResult>(callback).Url, StringComparison.Ordinal);

        var resultContext = new DefaultHttpContext();
        resultContext.Request.Headers.Cookie = cookie;
        var result = fixture.CreateConnectionsController(resultContext).Get();
        var response = Assert.IsType<ConnectionsResponse>(Assert.IsType<OkObjectResult>(result.Result).Value);
        Assert.Equal(new OAuthFeedbackDto("github", "provider_timeout"), Assert.Single(response.OAuthFeedback!));
    }

    [Fact]
    public async Task CallbackRequiresSingleStateAndCodeBeforeProviderRequests()
    {
        var handler = new FakeGithubHandler("unused-token");
        var fixture = new OAuthFixture(handler);
        var firstStartContext = new DefaultHttpContext();
        var firstStart = StartProvider(fixture, firstStartContext, "github");
        var firstState = QueryHelpers.ParseQuery(new Uri(firstStart.Url!).Query)["state"].ToString();
        var cookie = firstStartContext.Response.Headers.SetCookie.ToString().Split(';')[0];
        var secondStartContext = new DefaultHttpContext();
        secondStartContext.Request.Headers.Cookie = cookie;
        var secondStart = StartProvider(fixture, secondStartContext, "github");
        var secondState = QueryHelpers.ParseQuery(new Uri(secondStart.Url!).Query)["state"].ToString();

        var ambiguousStateContext = new DefaultHttpContext();
        ambiguousStateContext.Request.Headers.Cookie = cookie;
        ambiguousStateContext.Request.QueryString = new QueryString(
            $"?state={firstState}&state={secondState}&code=authorization-code");
        var ambiguousState = await fixture.CreateController(ambiguousStateContext)
            .Callback("github", CancellationToken.None);
        Assert.Contains("reason=state_mismatch", Assert.IsType<RedirectResult>(ambiguousState).Url, StringComparison.Ordinal);

        var invalidStateResultContext = new DefaultHttpContext();
        invalidStateResultContext.Request.Headers.Cookie = cookie;
        var invalidStateGet = fixture.CreateConnectionsController(invalidStateResultContext).Get();
        var invalidStateResponse = Assert.IsType<ConnectionsResponse>(Assert.IsType<OkObjectResult>(invalidStateGet.Result).Value);
        Assert.Empty(invalidStateResponse.OAuthFeedback!);

        var missingStateContext = new DefaultHttpContext();
        missingStateContext.Request.Headers.Cookie = cookie;
        missingStateContext.Request.QueryString = new QueryString("?code=authorization-code");
        var missingState = await fixture.CreateController(missingStateContext)
            .Callback("github", CancellationToken.None);
        Assert.Contains("reason=state_mismatch", Assert.IsType<RedirectResult>(missingState).Url, StringComparison.Ordinal);

        var missingStateResultContext = new DefaultHttpContext();
        missingStateResultContext.Request.Headers.Cookie = cookie;
        var missingStateGet = fixture.CreateConnectionsController(missingStateResultContext).Get();
        var missingStateResponse = Assert.IsType<ConnectionsResponse>(Assert.IsType<OkObjectResult>(missingStateGet.Result).Value);
        Assert.Empty(missingStateResponse.OAuthFeedback!);

        var ambiguousCodeContext = new DefaultHttpContext();
        ambiguousCodeContext.Request.Headers.Cookie = cookie;
        ambiguousCodeContext.Request.QueryString = new QueryString(
            $"?state={secondState}&code=first&code=second");
        var ambiguousCode = await fixture.CreateController(ambiguousCodeContext)
            .Callback("github", CancellationToken.None);
        Assert.Contains("reason=missing_code", Assert.IsType<RedirectResult>(ambiguousCode).Url, StringComparison.Ordinal);

        var thirdStartContext = new DefaultHttpContext();
        thirdStartContext.Request.Headers.Cookie = cookie;
        var thirdStart = StartProvider(fixture, thirdStartContext, "github");
        var thirdState = QueryHelpers.ParseQuery(new Uri(thirdStart.Url!).Query)["state"].ToString();
        var missingCodeContext = new DefaultHttpContext();
        missingCodeContext.Request.Headers.Cookie = cookie;
        missingCodeContext.Request.QueryString = new QueryString($"?state={thirdState}");
        var missingCode = await fixture.CreateController(missingCodeContext)
            .Callback("github", CancellationToken.None);
        Assert.Contains("reason=missing_code", Assert.IsType<RedirectResult>(missingCode).Url, StringComparison.Ordinal);
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task UnknownStateCallbacksDoNotCreateOrEvictOAuthFeedback()
    {
        var fixture = new OAuthFixture(new FakeGithubHandler("unused-token"));
        var startContext = new DefaultHttpContext();
        var start = StartProvider(fixture, startContext, "github");
        var cookie = startContext.Response.Headers.SetCookie.ToString().Split(';')[0];
        var issuedState = QueryHelpers.ParseQuery(new Uri(start.Url!).Query)["state"].ToString();

        var deniedContext = new DefaultHttpContext();
        deniedContext.Request.Headers.Cookie = cookie;
        deniedContext.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["state"] = issuedState,
            ["error"] = "access_denied"
        });
        await fixture.CreateController(deniedContext).Callback("github", CancellationToken.None);

        for (var attempt = 0; attempt < OAuthStateTransactions.MaximumPendingTransactions + 1; attempt++)
        {
            var forgedContext = new DefaultHttpContext();
            forgedContext.Request.Headers.Cookie = cookie;
            forgedContext.Request.QueryString = QueryString.Create("state", $"attacker-state-{attempt}");
            await fixture.CreateController(forgedContext).Callback("github", CancellationToken.None);
        }

        var resultContext = new DefaultHttpContext();
        resultContext.Request.Headers.Cookie = cookie;
        var get = fixture.CreateConnectionsController(resultContext).Get();
        var response = Assert.IsType<ConnectionsResponse>(Assert.IsType<OkObjectResult>(get.Result).Value);
        Assert.Equal(new OAuthFeedbackDto("github", "access_denied"), Assert.Single(response.OAuthFeedback!));
    }

    [Fact]
    public async Task ExpiredServerIssuedStateSurvivesCleanupTriggeredByAnotherStart()
    {
        var now = new DateTimeOffset(2026, 9, 30, 12, 0, 0, TimeSpan.Zero);
        var clock = new MutableTimeProvider(now);
        var fixture = new OAuthFixture(new FakeGithubHandler("unused-token"), timeProvider: clock);
        var startContext = new DefaultHttpContext();
        var start = StartProvider(fixture, startContext, "github");
        var cookie = startContext.Response.Headers.SetCookie.ToString().Split(';')[0];
        var issuedState = QueryHelpers.ParseQuery(new Uri(start.Url!).Query)["state"].ToString();
        clock.Advance(TimeSpan.FromMinutes(11));

        var laterStartContext = new DefaultHttpContext();
        laterStartContext.Request.Headers.Cookie = cookie;
        var laterStart = StartProvider(fixture, laterStartContext, "google");
        Assert.IsType<RedirectResult>(laterStart);

        var callbackContext = new DefaultHttpContext();
        callbackContext.Request.Headers.Cookie = cookie;
        callbackContext.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["state"] = issuedState,
            ["error"] = "access_denied"
        });
        var callback = await fixture.CreateController(callbackContext).Callback("github", CancellationToken.None);

        Assert.Contains("reason=state_mismatch", Assert.IsType<RedirectResult>(callback).Url, StringComparison.Ordinal);
        var resultContext = new DefaultHttpContext();
        resultContext.Request.Headers.Cookie = cookie;
        var get = fixture.CreateConnectionsController(resultContext).Get();
        var response = Assert.IsType<ConnectionsResponse>(Assert.IsType<OkObjectResult>(get.Result).Value);
        Assert.Equal(new OAuthFeedbackDto("github", "state_mismatch"), Assert.Single(response.OAuthFeedback!));
    }

    [Fact]
    public void ForcedDemoBlocksConfiguredProviderStart()
    {
        var handler = new FakeGithubHandler("unused-token");
        var fixture = new OAuthFixture(handler, forceDemo: true);
        Assert.True(fixture.Connections.IsDemoMode);

        var context = new DefaultHttpContext();
        var result = StartProvider(fixture, context, "github");

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Contains("reason=demo_mode", redirect.Url, StringComparison.Ordinal);
        Assert.DoesNotContain("github.com/login/oauth/authorize", redirect.Url, StringComparison.Ordinal);
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task GithubAuthorizationExchangesCodeOnServerAndConsumesStateOnce()
    {
        const string accessToken = "access-token-test-sentinel";
        const string refreshToken = "refresh-token-test-sentinel";
        var handler = new FakeGithubHandler(accessToken);
        var fixture = new OAuthFixture(handler);
        var startContext = new DefaultHttpContext();
        var start = StartProvider(fixture, startContext, "github");
        var authorization = new Uri(start.Url!);
        var authorizationParameters = QueryHelpers.ParseQuery(authorization.Query);
        var state = authorizationParameters["state"].ToString();
        var challenge = authorizationParameters["code_challenge"].ToString();
        var cookie = startContext.Response.Headers.SetCookie.ToString().Split(';')[0];

        Assert.Equal("S256", authorizationParameters["code_challenge_method"]);
        Assert.Equal(43, state.Length);
        Assert.Equal(43, challenge.Length);
        Assert.DoesNotContain("client_secret", authorization.Query, StringComparison.OrdinalIgnoreCase);

        var callbackContext = new DefaultHttpContext();
        callbackContext.Request.Headers.Cookie = cookie;
        callbackContext.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["state"] = state,
            ["code"] = "short-lived-authorization-code"
        });
        var callback = await fixture.CreateController(callbackContext)
            .Callback("github", CancellationToken.None);

        var redirect = Assert.IsType<RedirectResult>(callback);
        Assert.Contains("oauth=connected", redirect.Url, StringComparison.Ordinal);
        Assert.Equal(2, handler.RequestCount);
        Assert.Equal(43, handler.CodeVerifierLength);
        Assert.Equal(challenge, Pkce.CreateChallenge(handler.CodeVerifier));

        var sessionId = cookie[(cookie.IndexOf('=') + 1)..];
        var workspace = fixture.Store.Find(sessionId);
        Assert.NotNull(workspace);
        var snapshot = fixture.Connections.GetSnapshot(workspace!);
        var connection = snapshot.Connections.Single(item => item.Provider == "github");
        Assert.Equal("connected", connection.Status);
        Assert.Equal("OAuth Engineer", connection.Profile!.DisplayName);
        Assert.Equal("case-reviewer", connection.Profile.Identifier);
        Assert.True(connection.CanRefreshAccessToken);
        Assert.NotNull(connection.AccessTokenExpiresAt);
        Assert.Empty(connection.GrantedScopes ?? []);

        var publicJson = JsonSerializer.Serialize(snapshot);
        Assert.DoesNotContain(accessToken, publicJson, StringComparison.Ordinal);
        Assert.DoesNotContain(refreshToken, publicJson, StringComparison.Ordinal);
        Assert.DoesNotContain("\"AccessToken\":", publicJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("\"RefreshToken\":", publicJson, StringComparison.OrdinalIgnoreCase);

        var replayContext = new DefaultHttpContext();
        replayContext.Request.Headers.Cookie = cookie;
        replayContext.Request.QueryString = callbackContext.Request.QueryString;
        var replay = await fixture.CreateController(replayContext)
            .Callback("github", CancellationToken.None);

        var rejectedReplay = Assert.IsType<RedirectResult>(replay);
        Assert.Contains("reason=state_mismatch", rejectedReplay.Url, StringComparison.Ordinal);
        Assert.Equal(2, handler.RequestCount);

        var replayResultContext = new DefaultHttpContext();
        replayResultContext.Request.Headers.Cookie = cookie;
        var replayResult = fixture.CreateConnectionsController(replayResultContext).Get();
        var replayResponse = Assert.IsType<ConnectionsResponse>(Assert.IsType<OkObjectResult>(replayResult.Result).Value);
        Assert.Empty(replayResponse.OAuthFeedback!);
    }

    [Fact]
    public async Task GoogleAuthorizationValidatesPkceAndKeepsTokensOutOfTheProfileResponse()
    {
        const string accessToken = "google-access-token-test-sentinel";
        const string refreshToken = "google-refresh-token-test-sentinel";
        var handler = new FakeGoogleHandler(accessToken, refreshToken);
        var fixture = new OAuthFixture(handler);
        var startContext = new DefaultHttpContext();
        var start = StartProvider(fixture, startContext, "google");
        var parameters = QueryHelpers.ParseQuery(new Uri(start.Url!).Query);
        var cookie = startContext.Response.Headers.SetCookie.ToString().Split(';')[0];

        Assert.Equal("select_account consent", parameters["prompt"]);
        Assert.Equal("offline", parameters["access_type"]);
        Assert.Equal("S256", parameters["code_challenge_method"]);
        Assert.Equal("openid email profile", parameters["scope"]);

        var callbackContext = new DefaultHttpContext();
        callbackContext.Request.Headers.Cookie = cookie;
        callbackContext.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["state"] = parameters["state"].ToString(),
            ["code"] = "short-lived-authorization-code"
        });
        var callback = await fixture.CreateController(callbackContext)
            .Callback("google", CancellationToken.None);

        var redirect = Assert.IsType<RedirectResult>(callback);
        Assert.Contains("oauth=connected", redirect.Url, StringComparison.Ordinal);
        Assert.Equal(43, handler.CodeVerifierLength);
        Assert.Equal(2, handler.RequestCount);
        var sessionId = cookie[(cookie.IndexOf('=') + 1)..];
        var snapshot = fixture.Connections.GetSnapshot(fixture.Store.Find(sessionId)!);
        var google = Assert.Single(snapshot.Connections, item => item.Provider == "google");
        Assert.Equal("connected", google.Status);
        Assert.Equal("creator@example.test", google.Profile?.Email);
        Assert.Equal("google-subject-test-only", fixture.Store.Find(sessionId)!.Connections[ProviderId.Google].Profile?.AccountKey);

        var publicJson = JsonSerializer.Serialize(snapshot);
        Assert.DoesNotContain(accessToken, publicJson, StringComparison.Ordinal);
        Assert.DoesNotContain(refreshToken, publicJson, StringComparison.Ordinal);
        Assert.DoesNotContain("google-subject-test-only", publicJson, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GoogleCallbackReportsWhenNoRefreshTokenWasReturned()
    {
        var fixture = new OAuthFixture(new FakeGoogleWithoutRefreshHandler());
        var startContext = new DefaultHttpContext();
        var start = StartProvider(fixture, startContext, "google");
        var parameters = QueryHelpers.ParseQuery(new Uri(start.Url!).Query);
        var cookie = startContext.Response.Headers.SetCookie.ToString().Split(';')[0];
        var callbackContext = new DefaultHttpContext();
        callbackContext.Request.Headers.Cookie = cookie;
        callbackContext.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["state"] = parameters["state"].ToString(),
            ["code"] = "short-lived-authorization-code"
        });

        var callback = await fixture.CreateController(callbackContext)
            .Callback("google", CancellationToken.None);

        var redirect = Assert.IsType<RedirectResult>(callback);
        Assert.Contains("oauth=connected", redirect.Url, StringComparison.Ordinal);
        Assert.Contains("reason=missing_refresh_token", redirect.Url, StringComparison.Ordinal);
        var sessionId = cookie[(cookie.IndexOf('=') + 1)..];
        var google = Assert.Single(fixture.Connections.GetSnapshot(fixture.Store.Find(sessionId)!).Connections,
            item => item.Provider == "google");
        Assert.Equal("reauth_required", google.Status);
        Assert.Contains("refresh token", google.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DiscordCallbackUsesStateWithoutPkceAndReturnsOnlyTheNormalizedProfile()
    {
        const string accessToken = "discord-access-token-test-sentinel";
        const string refreshToken = "discord-refresh-token-test-sentinel";
        var handler = new FakeDiscordHandler(accessToken, refreshToken);
        var fixture = new OAuthFixture(handler);
        var startContext = new DefaultHttpContext();
        var start = StartProvider(fixture, startContext, "discord");
        var authorization = new Uri(start.Url!);
        var parameters = QueryHelpers.ParseQuery(authorization.Query);
        var cookie = startContext.Response.Headers.SetCookie.ToString().Split(';')[0];

        Assert.Equal("https://discord.com/oauth2/authorize", authorization.GetLeftPart(UriPartial.Path));
        Assert.Equal("identify", parameters["scope"]);
        Assert.False(parameters.ContainsKey("code_challenge"));
        Assert.False(parameters.ContainsKey("code_challenge_method"));
        Assert.Equal("consent", parameters["prompt"]);

        var callbackContext = new DefaultHttpContext();
        callbackContext.Request.Headers.Cookie = cookie;
        callbackContext.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["state"] = parameters["state"].ToString(),
            ["code"] = "short-lived-authorization-code"
        });
        var callback = await fixture.CreateController(callbackContext)
            .Callback("discord", CancellationToken.None);

        Assert.Contains("oauth=connected", Assert.IsType<RedirectResult>(callback).Url, StringComparison.Ordinal);
        Assert.Equal(2, handler.RequestCount);
        Assert.DoesNotContain("code_verifier", handler.TokenForm.Keys, StringComparer.Ordinal);

        var sessionId = cookie[(cookie.IndexOf('=') + 1)..];
        var snapshot = fixture.Connections.GetSnapshot(fixture.Store.Find(sessionId)!);
        var discord = Assert.Single(snapshot.Connections, item => item.Provider == "discord");
        Assert.Equal("connected", discord.Status);
        Assert.Equal("Mira Dev", discord.Profile?.DisplayName);
        Assert.Equal("mira.dev", discord.Profile?.Identifier);
        Assert.Null(discord.Profile?.Email);
        Assert.Equal(new[] { "identify" }, discord.GrantedScopes);

        var publicJson = JsonSerializer.Serialize(snapshot);
        Assert.DoesNotContain(accessToken, publicJson, StringComparison.Ordinal);
        Assert.DoesNotContain(refreshToken, publicJson, StringComparison.Ordinal);
        Assert.DoesNotContain("accountKey", publicJson, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OverbroadGithubGrantIsRejectedWithoutInvalidatingExistingConnection()
    {
        var fixture = new OAuthFixture(new GithubOverbroadScopeHandler());
        var startContext = new DefaultHttpContext();
        var start = StartProvider(fixture, startContext, "github");
        var authorization = new Uri(start.Url!);
        var parameters = QueryHelpers.ParseQuery(authorization.Query);
        var cookie = startContext.Response.Headers.SetCookie.ToString().Split(';')[0];
        var sessionId = cookie[(cookie.IndexOf('=') + 1)..];
        var workspace = fixture.Store.Find(sessionId)!;
        workspace.Connections[ProviderId.Github] = new StoredProviderConnection
        {
            Provider = ProviderId.Github,
            Status = "connected",
            AccessToken = "existing-access-token",
            RefreshToken = "existing-refresh-token",
            ConnectedAt = DateTimeOffset.UtcNow,
            Profile = new ProviderProfile("Existing profile", "reviewer", null, null, null)
            {
                AccountKey = "12345"
            }
        };

        var callbackContext = new DefaultHttpContext();
        callbackContext.Request.Headers.Cookie = cookie;
        callbackContext.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["state"] = parameters["state"].ToString(),
            ["code"] = "authorization-code"
        });
        var callback = await fixture.CreateController(callbackContext)
            .Callback("github", CancellationToken.None);

        var redirect = Assert.IsType<RedirectResult>(callback);
        Assert.Contains("reason=unexpected_provider_scopes", redirect.Url, StringComparison.Ordinal);
        Assert.Equal("connected", workspace.Connections[ProviderId.Github].Status);
        Assert.Equal("existing-refresh-token", workspace.Connections[ProviderId.Github].RefreshToken);
    }

    [Fact]
    public async Task DisconnectInvalidatesPendingProviderAuthorizationBeforeCodeExchange()
    {
        var handler = new FakeGithubHandler("unused-token");
        var fixture = new OAuthFixture(handler);
        var startContext = new DefaultHttpContext();
        var start = StartProvider(fixture, startContext, "github");
        var parameters = QueryHelpers.ParseQuery(new Uri(start.Url!).Query);
        var cookie = startContext.Response.Headers.SetCookie.ToString().Split(';')[0];
        var sessionId = cookie[(cookie.IndexOf('=') + 1)..];
        var workspace = fixture.Store.Find(sessionId)!;

        fixture.Connections.Disconnect(workspace, ProviderId.Github);

        var callbackContext = new DefaultHttpContext();
        callbackContext.Request.Headers.Cookie = cookie;
        callbackContext.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["state"] = parameters["state"].ToString(),
            ["code"] = "authorization-code"
        });
        var callback = await fixture.CreateController(callbackContext)
            .Callback("github", CancellationToken.None);

        var redirect = Assert.IsType<RedirectResult>(callback);
        Assert.Contains("reason=state_mismatch", redirect.Url, StringComparison.Ordinal);
        Assert.Equal(0, handler.RequestCount);
        Assert.False(workspace.Connections.ContainsKey(ProviderId.Github));
    }

    private sealed class OAuthFixture(
        HttpMessageHandler handler,
        bool forceDemo = false,
        string environmentName = "Development",
        TimeProvider? timeProvider = null)
    {
        private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
        private readonly IConfiguration _configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["App:PublicOrigin"] = "http://localhost:5223",
                ["App:FrontendOrigin"] = "http://localhost:4200",
                ["App:ForceDemo"] = forceDemo.ToString(),
                ["OAuth:Github:ClientId"] = "github-client-id",
                ["OAuth:Github:ClientSecret"] = "github-client-secret",
                ["OAuth:Google:ClientId"] = "google-client-id",
                ["OAuth:Google:ClientSecret"] = "google-client-secret",
                ["OAuth:Discord:ClientId"] = "discord-client-id",
                ["OAuth:Discord:ClientSecret"] = "discord-client-secret"
            })
            .Build();

        public InMemoryWorkspaceStore Store { get; } = new(timeProvider ?? TimeProvider.System);
        private WorkspaceSessionManager Sessions => new(Store, new TestWebHostEnvironment(environmentName));
        private OAuthProviderClient Providers => new(_configuration, new FakeClientFactory(handler), _clock);
        public ConnectionService Connections => new(
            Providers,
            _clock);

        public OAuthController CreateController(DefaultHttpContext context)
        {
            var controller = new OAuthController(
                Sessions,
                Providers,
                Connections,
                _clock,
                NullLogger<OAuthController>.Instance)
            {
                ControllerContext = new ControllerContext { HttpContext = context }
            };
            return controller;
        }

        public ConnectionsController CreateConnectionsController(DefaultHttpContext context) => new(
            Sessions,
            Connections)
        {
            ControllerContext = new ControllerContext { HttpContext = context }
        };

        public SessionController CreateSessionController(DefaultHttpContext context) => new(
            Sessions,
            Connections)
        {
            ControllerContext = new ControllerContext { HttpContext = context }
        };
    }

    private sealed class MutableTimeProvider(DateTimeOffset initialTime) : TimeProvider
    {
        private DateTimeOffset _now = initialTime;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan elapsed) => _now = _now.Add(elapsed);
    }

    private sealed class FakeClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class CountingProviderTransportHandler : HttpMessageHandler
    {
        private int _requestCount;

        public int RequestCount => Volatile.Read(ref _requestCount);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requestCount);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
        }
    }

    private sealed class FakeGoogleHandler(string accessToken, string refreshToken) : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public int CodeVerifierLength { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            if (request.RequestUri?.Host == "oauth2.googleapis.com")
            {
                var form = QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(cancellationToken));
                Assert.Equal("short-lived-authorization-code", form["code"]);
                Assert.Equal("authorization_code", form["grant_type"]);
                Assert.Equal("google-client-secret", form["client_secret"]);
                CodeVerifierLength = form["code_verifier"].ToString().Length;
                return Json(HttpStatusCode.OK,
                    "{\"access_token\":\"" + accessToken + "\","
                    + "\"refresh_token\":\"" + refreshToken + "\",\"expires_in\":3600,"
                    + "\"scope\":\"openid email profile\"}");
            }

            Assert.Equal("openidconnect.googleapis.com", request.RequestUri?.Host);
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            Assert.Equal(accessToken, request.Headers.Authorization?.Parameter);
            return Json(HttpStatusCode.OK,
                "{\"sub\":\"google-subject-test-only\",\"email\":\"creator@example.test\","
                + "\"email_verified\":true,\"name\":\"Creator\"}");
        }

        private static HttpResponseMessage Json(HttpStatusCode statusCode, string value)
        {
            var response = new HttpResponseMessage(statusCode) { Content = new StringContent(value) };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            return response;
        }
    }

    private sealed class FakeGoogleWithoutRefreshHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.RequestUri?.Host == "oauth2.googleapis.com")
            {
                var form = QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(cancellationToken));
                Assert.Equal("authorization_code", form["grant_type"]);
                Assert.Equal(43, form["code_verifier"].ToString().Length);
                return Json(HttpStatusCode.OK,
                    "{\"access_token\":\"google-access-token-test-only\","
                    + "\"expires_in\":3600,\"scope\":\"openid email profile\"}");
            }

            Assert.Equal("openidconnect.googleapis.com", request.RequestUri?.Host);
            return Json(HttpStatusCode.OK,
                "{\"sub\":\"google-user-no-refresh\",\"name\":\"Creator\"}");
        }

        private static HttpResponseMessage Json(HttpStatusCode statusCode, string value)
        {
            var response = new HttpResponseMessage(statusCode) { Content = new StringContent(value) };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            return response;
        }
    }

    private sealed class FakeGithubHandler(string accessToken) : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public int CodeVerifierLength { get; private set; }
        public string CodeVerifier { get; private set; } = string.Empty;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            if (request.RequestUri?.Host == "github.com")
            {
                var form = QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(cancellationToken));
                Assert.Equal("authorization_code", form["grant_type"]);
                Assert.Equal("short-lived-authorization-code", form["code"]);
                Assert.Equal("github-client-secret", form["client_secret"]);
                CodeVerifier = form["code_verifier"].ToString();
                CodeVerifierLength = CodeVerifier.Length;
                return Json(HttpStatusCode.OK,
                    "{\"access_token\":\"" + accessToken + "\","
                    + "\"refresh_token\":\"refresh-token-test-sentinel\",\"expires_in\":28800,\"scope\":\"\"}");
            }

            Assert.Equal("api.github.com", request.RequestUri?.Host);
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            Assert.Equal(accessToken, request.Headers.Authorization?.Parameter);
            return Json(HttpStatusCode.OK,
                "{\"id\":12345,\"login\":\"case-reviewer\",\"name\":\"OAuth Engineer\","
                + "\"avatar_url\":\"https://avatars.example.test/reviewer.png\","
                + "\"html_url\":\"https://github.com/case-reviewer\"}");
        }

        private static HttpResponseMessage Json(HttpStatusCode statusCode, string value)
        {
            var response = new HttpResponseMessage(statusCode)
            {
                Content = new StringContent(value)
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            return response;
        }
    }

    private sealed class FakeDiscordHandler(string accessToken, string refreshToken) : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public Dictionary<string, string> TokenForm { get; private set; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            if (request.RequestUri?.Host == "discord.com"
                && request.RequestUri.AbsolutePath == "/api/oauth2/token")
            {
                TokenForm = QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(cancellationToken))
                    .ToDictionary(pair => pair.Key, pair => pair.Value.ToString());
                Assert.Equal("application/x-www-form-urlencoded", request.Content.Headers.ContentType?.MediaType);
                Assert.Equal("short-lived-authorization-code", TokenForm["code"]);
                Assert.Equal("discord-client-secret", TokenForm["client_secret"]);
                return Json(HttpStatusCode.OK,
                    "{\"access_token\":\"" + accessToken + "\","
                    + "\"refresh_token\":\"" + refreshToken + "\",\"expires_in\":604800,"
                    + "\"scope\":\"identify\"}");
            }

            Assert.Equal("/api/v10/users/@me", request.RequestUri?.AbsolutePath);
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            Assert.Equal(accessToken, request.Headers.Authorization?.Parameter);
            return Json(HttpStatusCode.OK,
                "{\"id\":\"4815162342\",\"username\":\"mira.dev\","
                + "\"global_name\":\"Mira Dev\",\"avatar\":\"avatarhash\"}");
        }

        private static HttpResponseMessage Json(HttpStatusCode statusCode, string value)
        {
            var response = new HttpResponseMessage(statusCode) { Content = new StringContent(value) };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            return response;
        }
    }

    private sealed class TimeoutGithubHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromException<HttpResponseMessage>(new OperationCanceledException("provider transport timed out"));
    }

    private sealed class GithubOverbroadScopeHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"access_token\":\"rejected-token\",\"scope\":\"repo\"}")
            });
    }

    private sealed class TestWebHostEnvironment(string environmentName) : IWebHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "OAuth.Flow.Tests";
        public string WebRootPath { get; set; } = string.Empty;
        public string ContentRootPath { get; set; } = string.Empty;
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
