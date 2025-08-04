
using Microsoft.AspNetCore.Mvc;

[Route("api/[controller]")]
[ApiController]
public class YoutubeController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly IYoutubeOAuthService _youtubeService;
    private readonly ILogger<YoutubeOAuthService> _logger;

    public YoutubeController(IYoutubeOAuthService googleService, ILogger<YoutubeOAuthService> logger, IConfiguration config)
    {
        _youtubeService = googleService;
        _logger = logger;
        _config = config;
    }

    [HttpGet("login")]
    public IActionResult Login()
    {
        var url = _youtubeService.GenerateOAuthUrl(_config["YoutubeOAuth:CallbackUrl"]);
        return Redirect(url);
    }
    [HttpGet("callback")]
    public async Task<IActionResult> Callback([FromQuery] string code)
    {
        if (string.IsNullOrEmpty(code))
            return BadRequest("Missing code");

        try
        {
            var token = await _youtubeService.ExchangeCodeOnTokenAsync(code, _config["YoutubeOAuth:CallbackUrl"]);
            return Ok(token);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during Google OAuth token exchange");
            return StatusCode(400, "Failed to exchange authorization code. It might be expired or already used.");
        }
    }
    [HttpGet("refresh")]
    public async Task<IActionResult> refresh(string code)
    {
        var token = await _youtubeService.RefreshTokenAsync(code);

        return Ok(token);
    }
}

