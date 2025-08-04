
public interface IGoogleAuthService
{
    string GetAuthorizationUrl();
    Task<GoogleTokenResponse> ExchangeCodeForTokenAsync(string code);
    Task<GoogleUserInfo> GetUserInfoAsync(string accessToken);
    Task<GoogleTokenResponse> RefreshAccessTokenAsync(string refreshToken);
}
