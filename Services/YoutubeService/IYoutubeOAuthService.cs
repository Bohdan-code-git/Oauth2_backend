public interface IYoutubeOAuthService
{
    string GenerateOAuthUrl(string state = null);
    Task<GoogleTokenResponse> ExchangeCodeOnTokenAsync(string code);
    Task<GoogleTokenResponse> RefreshTokenAsync(string refreshToken);
}

