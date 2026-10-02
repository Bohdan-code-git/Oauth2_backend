using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

[ApiController]
[Route("api/session")]
public sealed class SessionController(
    WorkspaceSessionManager sessions,
    ConnectionService connections) : ControllerBase
{
    [HttpGet]
    [EnableRateLimiting("workspace-init")]
    public ActionResult<SessionResponse> Get()
    {
        try
        {
            var session = sessions.GetOrCreate(HttpContext);
            return Ok(new SessionResponse(
                "Switchboard",
                "browser_workspace",
                connections.IsDemoMode ? "demo" : "live",
                session.CsrfToken,
                session.WorkspaceRecoveryRequired));
        }
        catch (WorkspaceCapacityException)
        {
            Response.Headers.RetryAfter = "60";
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "workspace_capacity" });
        }
        catch (WorkspaceCreationRateLimitException error)
        {
            Response.Headers.RetryAfter = error.RetryAfterSeconds.ToString();
            return StatusCode(StatusCodes.Status429TooManyRequests, new { error = "workspace_creation_rate_limited" });
        }
    }

    [HttpPost("workspace/clear")]
    public IActionResult ClearWorkspace()
    {
        var session = sessions.Find(HttpContext);
        if (session is null)
            return NoContent();
        if (!sessions.HasValidCsrfToken(Request, session))
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "csrf_validation_failed" });

        sessions.ClearWorkspace(HttpContext, session);
        return NoContent();
    }
}
