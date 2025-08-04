using System.Text.Json;
using System.Web;


public class YoutubeOAuthService : IYoutubeOAuthService
{
    private readonly IConfiguration _config;
    private const string TokenEndpoint = "https://oauth2.googleapis.com/token";
    private const string AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    private const string Scope = "https://www.googleapis.com/auth/youtube";
    private readonly ILogger<YoutubeOAuthService> _logger;
    private readonly HttpClient _http;

    public YoutubeOAuthService(HttpClient http, ILogger<YoutubeOAuthService> logger, IConfiguration config)
    {
        _logger = logger;
        _http = http;
        _config = config;
    }

    public string GenerateOAuthUrl(string state = null)
    {
        var queryParams = HttpUtility.ParseQueryString(string.Empty);
        queryParams["client_id"] = _config["YoutubeOAuth:ClientId"];
        queryParams["redirect_uri"] = _config["YoutubeOAuth:CallbackUrl"];
        queryParams["response_type"] = "code";
        queryParams["scope"] = Scope;
        queryParams["access_type"] = "offline";
        queryParams["prompt"] = "consent";
        if (!string.IsNullOrEmpty(state))
            queryParams["state"] = state;

        return $"{AuthorizationEndpoint}?{queryParams}";
    }

    public async Task<GoogleTokenResponse> ExchangeCodeOnTokenAsync(string code)
    {
        var data = new Dictionary<string, string>
    {
        { "code", code },
        { "client_id", _config["YoutubeOAuth:ClientId"] },
        { "client_secret", _config["YoutubeOAuth:ClientSecret"] },
        { "redirect_uri", _config["YoutubeOAuth:CallbackUrl"] },
        { "grant_type", "authorization_code" }
    };

        var response = await _http.PostAsync(TokenEndpoint, new FormUrlEncodedContent(data));
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Ошибка обмена кода на токен. Статус: {StatusCode}, Ответ: {Content}", response.StatusCode, content);
            throw new HttpRequestException($"Ошибка обмена кода на токен: {content}");
        }

        return JsonSerializer.Deserialize<GoogleTokenResponse>(content, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    }

    public async Task<GoogleTokenResponse> RefreshTokenAsync(string refreshToken)
    {
        var data = new Dictionary<string, string>
        {
            { "refresh_token", refreshToken },
            { "client_id", _config["YoutubeOAuth:ClientId"] },
            { "client_secret", _config["YoutubeOAuth:ClientSecret"] },
            { "grant_type", "refresh_token" }
        };

        var response = await _http.PostAsync(TokenEndpoint, new FormUrlEncodedContent(data));
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<GoogleTokenResponse>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    }
}
