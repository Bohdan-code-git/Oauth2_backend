using Microsoft.AspNetCore.Mvc;


[Route("api/[controller]")]
public class GithubController : Controller
{
    private readonly GitHubOAuthService _githubService;

    public GithubController(GitHubOAuthService githubService)
    {
        _githubService = githubService;
    }

    [HttpGet("login")]
    public IActionResult Login()
    {
        var url = _githubService.GetAuthorizationUrl();
        return Redirect(url);
    }

    [HttpGet("callback")]
    public async Task<IActionResult> Callback([FromQuery] string code)
    {
        if (string.IsNullOrEmpty(code))
            return BadRequest(new { error = "Missing code" });

        var token = await _githubService.ExchangeCodeForToken(code);
        var userInfo = await _githubService.GetGitHubUser(token);

        return Ok(new
        {
            access_token = token,
            user = userInfo
        });
    }
}

