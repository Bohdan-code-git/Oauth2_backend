using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;

[ApiController]
[Route("api")]
public sealed class OAuthController(
    WorkspaceSessionManager sessions,
    OAuthProviderClient providers,
    ConnectionService connections,
    TimeProvider clock,
    ILogger<OAuthController> logger) : ControllerBase
{
    [HttpGet("oauth/providers")]
    public ActionResult<OAuthProvidersResponse> GetProviders() =>
        Ok(providers.GetPublicProviderConfiguration());

    [HttpPost("connections/{provider}/start")]
    [EnableRateLimiting("oauth-start")]
    public IActionResult Start(
        string provider,
        [FromForm] string? csrfToken = null)
    {
        if (!ProviderNames.TryParse(provider, out var providerId))
            return NotFound(new { error = "provider_not_found" });

        var session = sessions.Find(HttpContext);
        if (session is null)
            return RedirectToFrontend(providerId, "error", "session_expired");
        if (!sessions.HasValidCsrfFormToken(Request, session, csrfToken))
            return RedirectToFrontend(providerId, "error", "csrf_validation_failed");

        if (!providers.IsConfigured(providerId))
            return RedirectToFrontend(providerId, "error", "not_configured");
        if (connections.IsDemoMode)
            return RedirectToFrontend(providerId, "error", "demo_mode");

        OAuthTransaction transaction;
        try
        {
            transaction = session.PendingOAuth.Create(
                providerId,
                clock.GetUtcNow(),
                session.GetProviderGeneration(providerId),
                providers.SupportsPkce(providerId));
        }
        catch (OAuthTransactionCapacityException error)
        {
            Response.Headers.RetryAfter = error.RetryAfterSeconds.ToString(
                System.Globalization.CultureInfo.InvariantCulture);
            return StatusCode(StatusCodes.Status429TooManyRequests, new { error = "pending_oauth_capacity" });
        }
        var challenge = transaction.CodeVerifier is null
            ? null
            : Pkce.CreateChallenge(transaction.CodeVerifier);
        var authorizationUrl = providers.BuildAuthorizationUrl(
            providerId,
            transaction.State,
            challenge);

        Response.Headers["Referrer-Policy"] = "no-referrer";
        return Redirect(authorizationUrl);
    }

    [HttpGet("oauth/{provider}/callback")]
    public async Task<IActionResult> Callback(
        string provider,
        CancellationToken cancellationToken)
    {
        Response.Headers["Referrer-Policy"] = "no-referrer";

        if (!ProviderNames.TryParse(provider, out var providerId))
            return NotFound();

        var session = sessions.Find(HttpContext);
        if (session is null)
            return RedirectToFrontend(
                providerId,
                "error",
                "session_expired");

        var state = SingleQueryValue(Request.Query, "state");
        if (!session.PendingOAuth.TryConsume(
                state,
                providerId,
                clock.GetUtcNow(),
                out var transaction,
                out var knownExpired)
            || transaction is null)
        {
            if (knownExpired)
                session.SetOAuthFeedback(providerId, "state_mismatch");
            return RedirectToFrontend(providerId, "error", "state_mismatch");
        }

        var providerError = SingleQueryValue(Request.Query, "error");
        if (!string.IsNullOrWhiteSpace(providerError))
        {
            var reason = OAuthCallbackErrors.Map(providerError);
            session.SetOAuthFeedback(providerId, SafeReason(reason));
            return RedirectToFrontend(providerId, "error", reason);
        }

        var code = SingleQueryValue(Request.Query, "code");
        if (string.IsNullOrWhiteSpace(code) || code.Length > 4096)
        {
            session.SetOAuthFeedback(providerId, "missing_code");
            return RedirectToFrontend(providerId, "error", "missing_code");
        }

        try
        {
            await connections.CompleteAuthorizationAsync(
                session,
                providerId,
                code,
                transaction.CodeVerifier,
                transaction.ConnectionGeneration,
                cancellationToken);

            session.Connections.TryGetValue(providerId, out var completedConnection);
            var reason = completedConnection?.StatusReason == "missing_refresh_token"
                ? "missing_refresh_token"
                : null;
            return RedirectToFrontend(providerId, "connected", reason);
        }
        catch (ProviderRequestException error)
        {
            logger.LogWarning(
                "OAuth callback failed for provider {Provider}; category {Category}",
                providerId.ToSlug(),
                error.Reason);
            session.SetOAuthFeedback(providerId, SafeReason(error.Reason));
            return RedirectToFrontend(providerId, "error", error.Reason);
        }
    }

    private RedirectResult RedirectToFrontend(
        ProviderId provider,
        string result,
        string? reason)
    {
        var query = new Dictionary<string, string?>
        {
            ["oauth"] = result,
            ["provider"] = provider.ToSlug()
        };
        if (!string.IsNullOrWhiteSpace(reason))
            query["reason"] = SafeReason(reason);

        var target = QueryHelpers.AddQueryString(
            $"{providers.GetFrontendOrigin()}/",
            query);
        return Redirect(target);
    }

    private static string? SingleQueryValue(IQueryCollection query, string key) =>
        query.TryGetValue(key, out var values) && values.Count == 1
            ? values[0]
            : null;

    private static string SafeReason(string reason) => reason switch
    {
        "demo_mode" => "demo_mode",
        "not_configured" => "not_configured",
        "session_expired" => "session_expired",
        "state_mismatch" => "state_mismatch",
        "csrf_validation_failed" => "csrf_validation_failed",
        "access_denied" => "access_denied",
        "provider_error" => "provider_error",
        "missing_code" => "missing_code",
        "authorization_cancelled" => "authorization_cancelled",
        "authorization_required" => "authorization_required",
        "provider_timeout" => "provider_timeout",
        "provider_unavailable" => "provider_unavailable",
        "provider_forbidden" => "provider_forbidden",
        "invalid_token_response" => "invalid_token_response",
        "invalid_provider_response" => "invalid_provider_response",
        "invalid_provider_profile" => "invalid_provider_profile",
        "unexpected_provider_scopes" => "unexpected_provider_scopes",
        "missing_required_scopes" => "missing_required_scopes",
        "unverified_provider_scopes" => "unverified_provider_scopes",
        "provider_not_configured" => "not_configured",
        "missing_refresh_token" => "missing_refresh_token",
        _ => "provider_error"
    };
}

public static class OAuthCallbackErrors
{
    public static string Map(string? providerError) =>
        string.Equals(providerError, "access_denied", StringComparison.Ordinal)
            ? "access_denied"
            : "provider_error";
}
