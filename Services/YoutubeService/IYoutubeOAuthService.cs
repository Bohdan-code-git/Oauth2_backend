public interface IYoutubeOAuthService
{
    string GenerateOAuthUrl(string redirectUri, string state = null);
    Task<GoogleTokenResponse> ExchangeCodeOnTokenAsync(string code, string redirectUri);
    Task<GoogleTokenResponse> RefreshTokenAsync(string refreshToken);
}

