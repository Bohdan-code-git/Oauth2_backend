using System.Net.Http.Headers;
using System.Text.Json;

public class GitHubOAuthService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _config;

    public GitHubOAuthService(HttpClient httpClient, IConfiguration config)
    {
        _httpClient = httpClient;
        _config = config;
    }

    public string GetAuthorizationUrl()
    {
        var clientId = _config["GitHubOAuth:ClientId"];
        var callback = _config["GitHubOAuth:CallbackUrl"];

        return $"https://github.com/login/oauth/authorize?client_id={clientId}&redirect_uri={callback}&scope=read:user";
    }

    public async Task<string> ExchangeCodeForToken(string code)
    {
        var requestData = new Dictionary<string, string>
        {
            ["client_id"] = _config["GitHubOAuth:ClientId"],
            ["client_secret"] = _config["GitHubOAuth:ClientSecret"],
            ["code"] = code,
            ["redirect_uri"] = _config["GitHubOAuth:CallbackUrl"]
        };

        var request = new HttpRequestMessage(HttpMethod.Post, "https://github.com/login/oauth/access_token")
        {
            Content = new FormUrlEncodedContent(requestData)
        };

        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        var response = await _httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        var tokenData = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
        return tokenData?["access_token"] ?? throw new Exception("Token not found");
    }

    public async Task<string> GetGitHubUser(string accessToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.UserAgent.ParseAdd("MyApp");

        var response = await _httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStringAsync(); // JSON with GitHub user info
    }
}