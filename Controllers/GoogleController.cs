using Microsoft.AspNetCore.Mvc;


[Route("api/[controller]")]
[ApiController]
public class GoogleController : ControllerBase
{
    private readonly IGoogleAuthService _googleAuthService;

    public GoogleController(IGoogleAuthService googleAuthService)
    {
        _googleAuthService = googleAuthService;
    }

    [HttpGet("login")]
    public IActionResult Login()
    {
        var url = _googleAuthService.GetAuthorizationUrl();
        return Redirect(url);
    }

    [HttpGet("callback")]
    public async Task<IActionResult> Callback([FromQuery] string code)
    {
        if (string.IsNullOrEmpty(code))
            return BadRequest("Authorization code is missing.");

        var tokenResponse = await _googleAuthService.ExchangeCodeForTokenAsync(code);

        // Можно сразу получить user info
        var userInfo = await _googleAuthService.GetUserInfoAsync(tokenResponse.Access_token!);

        // Возвращаем всё — токены и user info
        return Ok(new
        {
            Tokens = tokenResponse,
            User = userInfo
        });
    }
    [HttpGet("refresh")]
    public async Task<IActionResult> Refresh([FromQuery] string refreshToken)
    {
        if (string.IsNullOrEmpty(refreshToken))
            return BadRequest("Refresh token is required.");

        var newTokens = await _googleAuthService.RefreshAccessTokenAsync(refreshToken);

        return Ok(newTokens);
    }
}

