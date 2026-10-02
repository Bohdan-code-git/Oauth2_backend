using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

[ApiController]
[Route("api/connections")]
public sealed class ConnectionsController(
    WorkspaceSessionManager sessions,
    ConnectionService connections) : ControllerBase
{
    [HttpGet]
    [EnableRateLimiting("workspace-init")]
    public ActionResult<ConnectionsResponse> Get()
    {
        var session = sessions.Find(HttpContext);
        return session is null
            ? Unauthorized(new { error = "workspace_session_required" })
            : Ok(connections.GetSnapshot(session) with { OAuthFeedback = session.TakeOAuthFeedback() });
    }

    [HttpPost("refresh")]
    [EnableRateLimiting("profile-refresh")]
    public async Task<ActionResult<ConnectionsResponse>> Refresh(CancellationToken cancellationToken)
    {
        var session = sessions.Find(HttpContext);
        if (session is null)
            return Unauthorized(new { error = "workspace_session_required" });
        if (!sessions.HasValidCsrfToken(Request, session))
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "csrf_validation_failed" });

        return Ok(await connections.RefreshAsync(session, cancellationToken));
    }

    [HttpPost("{provider}/refresh")]
    [EnableRateLimiting("profile-refresh")]
    public async Task<ActionResult<ConnectionsResponse>> RefreshProvider(
        string provider,
        CancellationToken cancellationToken)
    {
        var session = sessions.Find(HttpContext);
        if (session is null)
            return Unauthorized(new { error = "workspace_session_required" });
        if (!sessions.HasValidCsrfToken(Request, session))
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "csrf_validation_failed" });
        if (!ProviderNames.TryParse(provider, out var providerId))
            return NotFound(new { error = "provider_not_found" });

        return Ok(await connections.RefreshProviderAsync(session, providerId, cancellationToken));
    }

    [HttpDelete("{provider}")]
    public IActionResult Disconnect(string provider)
    {
        var session = sessions.Find(HttpContext);
        if (session is null)
            return Unauthorized(new { error = "workspace_session_required" });
        if (!sessions.HasValidCsrfToken(Request, session))
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "csrf_validation_failed" });
        if (!ProviderNames.TryParse(provider, out var providerId))
            return NotFound(new { error = "provider_not_found" });
        if (connections.IsDemoMode)
            return Conflict(new { error = "demo_mode_read_only" });

        connections.Disconnect(session, providerId);
        return NoContent();
    }
}
