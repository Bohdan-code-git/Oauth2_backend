using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

public sealed class OAuthProviderClient(
    IConfiguration configuration,
    IHttpClientFactory httpClientFactory,
    TimeProvider clock)
{
    public bool IsConfigured(ProviderId provider)
    {
        var settings = GetSettings(provider);
        return IsUsable(settings.ClientId)
            && IsUsable(settings.ClientSecret)
            && HaveCompatibleOrigins();
    }

    public bool IsDemoMode()
    {
        if (bool.TryParse(configuration["App:ForceDemo"], out var forceDemo) && forceDemo)
            return true;

        return !Enum.GetValues<ProviderId>().Any(IsConfigured);
    }

    public bool SupportsPkce(ProviderId provider) =>
        provider is ProviderId.Google or ProviderId.Github;

    public string BuildAuthorizationUrl(
        ProviderId provider,
        string state,
        string? codeChallenge)
    {
        if (!IsConfigured(provider))
            throw new InvalidOperationException("Provider is not configured.");

        var settings = GetSettings(provider);
        var callbackUrl = GetCallbackUrl(provider);
        var query = new Dictionary<string, string?>
        {
            ["client_id"] = settings.ClientId,
            ["redirect_uri"] = callbackUrl,
            ["response_type"] = "code",
            ["state"] = state
        };
        if (SupportsPkce(provider))
        {
            if (string.IsNullOrWhiteSpace(codeChallenge))
                throw new ArgumentException("A PKCE S256 challenge is required for this provider.", nameof(codeChallenge));
            query["code_challenge"] = codeChallenge;
            query["code_challenge_method"] = "S256";
        }
        query["scope"] = string.Join(' ', GetScopes(provider));

        foreach (var parameter in GetAuthorizationParameters(provider))
            query[parameter.Name] = parameter.Value;

        return QueryHelpers.AddQueryString(GetAuthorizationEndpoint(provider), query);
    }

    public OAuthProvidersResponse GetPublicProviderConfiguration()
    {
        var providers = Enum.GetValues<ProviderId>()
            .Select(provider => new OAuthProviderInfoDto(
                provider.ToSlug(),
                provider.ToLabel(),
                IsConfigured(provider),
                GetAuthorizationEndpoint(provider),
                GetTokenEndpoint(provider),
                TryGetCallbackUrl(provider),
                "code",
                GetScopes(provider),
                SupportsPkce(provider) ? "S256" : null,
                GetProfileEndpoints(provider),
                GetAuthorizationParameters(provider)))
            .ToArray();

        return new OAuthProvidersResponse(IsDemoMode(), providers);
    }

    public async Task<ProviderToken> ExchangeCodeAsync(
        ProviderId provider,
        string code,
        string? codeVerifier,
        CancellationToken cancellationToken = default)
    {
        var settings = GetSettings(provider);
        var values = new Dictionary<string, string>
        {
            ["client_id"] = settings.ClientId!,
            ["client_secret"] = settings.ClientSecret!,
            ["code"] = code,
            ["redirect_uri"] = GetCallbackUrl(provider),
            ["grant_type"] = "authorization_code"
        };
        if (SupportsPkce(provider))
        {
            if (string.IsNullOrWhiteSpace(codeVerifier))
                throw new ProviderRequestException("missing_pkce_verifier");
            values["code_verifier"] = codeVerifier;
        }

        return await PostTokenRequestAsync(provider, values, cancellationToken);
    }

    public async Task<ProviderToken> RefreshAsync(
        ProviderId provider,
        string refreshToken,
        CancellationToken cancellationToken = default)
    {
        var settings = GetSettings(provider);
        var values = new Dictionary<string, string>
        {
            ["client_id"] = settings.ClientId!,
            ["client_secret"] = settings.ClientSecret!,
            ["refresh_token"] = refreshToken,
            ["grant_type"] = "refresh_token"
        };

        return await PostTokenRequestAsync(provider, values, cancellationToken);
    }

    public async Task<ProviderProfile?> GetProfileAsync(
        ProviderId provider,
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        using var request = provider switch
        {
            ProviderId.Google => new HttpRequestMessage(
                HttpMethod.Get,
                "https://openidconnect.googleapis.com/v1/userinfo"),
            ProviderId.Github => new HttpRequestMessage(
                HttpMethod.Get,
                "https://api.github.com/user"),
            ProviderId.Discord => new HttpRequestMessage(
                HttpMethod.Get,
                "https://discord.com/api/v10/users/@me"),
            _ => throw new ArgumentOutOfRangeException(nameof(provider))
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (provider == ProviderId.Github)
        {
            request.Headers.UserAgent.ParseAdd("Switchboard-Accounts/1.0");
            request.Headers.Add("X-GitHub-Api-Version", "2026-03-10");
        }

        using var document = await SendJsonAsync(
            provider,
            request,
            cancellationToken);

        return provider switch
        {
            ProviderId.Google => ParseGoogleProfile(document.RootElement),
            ProviderId.Github => ParseGithubProfile(document.RootElement),
            ProviderId.Discord => ParseDiscordProfile(document.RootElement),
            _ => throw new ArgumentOutOfRangeException(nameof(provider))
        };
    }

    public string GetFrontendOrigin()
    {
        var origin = configuration["RENDER_EXTERNAL_URL"]
            ?? configuration["App:FrontendOrigin"]
            ?? configuration["App:PublicOrigin"];
        if (!IsSafeOrigin(origin))
            throw new InvalidOperationException("App:FrontendOrigin must be an absolute HTTPS origin.");

        return origin!.TrimEnd('/');
    }

    private async Task<ProviderToken> PostTokenRequestAsync(
        ProviderId provider,
        Dictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, GetTokenEndpoint(provider))
        {
            Content = new FormUrlEncodedContent(values)
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var document = await SendJsonAsync(provider, request, cancellationToken);
        var root = document.RootElement;
        var isRefresh = values["grant_type"] == "refresh_token";
        var accessToken = GetString(root, "access_token");
        if (string.IsNullOrWhiteSpace(accessToken))
            throw new ProviderRequestException("invalid_token_response", requiresAuthorization: isRefresh);
        var scopeError = GetGrantedScopeError(provider, root, isAuthorizationCodeGrant: !isRefresh);
        if (scopeError is not null)
            throw new ProviderRequestException(scopeError, requiresAuthorization: isRefresh);

        var expiresIn = GetInt32(root, "expires_in");
        return new ProviderToken(
            accessToken,
            GetString(root, "refresh_token"),
            expiresIn is > 0 ? clock.GetUtcNow().AddSeconds(expiresIn.Value) : null,
            GetGrantedScopes(root));
    }

    private static IReadOnlyList<string>? GetGrantedScopes(JsonElement tokenResponse)
    {
        if (!tokenResponse.TryGetProperty("scope", out var scopeValue))
            return null;
        if (scopeValue.ValueKind != JsonValueKind.String)
            return [];

        return (scopeValue.GetString() ?? string.Empty)
            .Split([' ', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    private async Task<JsonDocument> SendJsonAsync(
        ProviderId provider,
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        HttpResponseMessage response;
        try
        {
            response = await httpClientFactory.CreateClient("providers")
                .SendAsync(request, cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new ProviderRequestException("provider_timeout");
        }
        catch (HttpRequestException)
        {
            throw new ProviderRequestException("provider_unavailable");
        }

        using (response)
        {
            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var isGoogleProvider = provider == ProviderId.Google;
                var insufficientProfilePermissions = response.StatusCode == HttpStatusCode.Forbidden
                    && isGoogleProvider
                    && (HasGoogleApiErrorReason(content, "insufficientPermissions")
                        || HasGoogleApiErrorCode(content, "insufficient_scope"));
                var providerQuotaExceeded = response.StatusCode == HttpStatusCode.Forbidden
                    && isGoogleProvider
                    && HasGoogleApiErrorReason(
                        content,
                        "quotaExceeded",
                        "dailyLimitExceeded",
                        "dailyLimitExceededUnreg",
                        "rateLimitExceeded",
                        "userRateLimitExceeded",
                        "userRateLimitExceededUnreg",
                        "servingLimitExceeded",
                        "concurrentLimitExceeded");
                var requiresAuthorization = response.StatusCode == HttpStatusCode.Unauthorized
                    || IsInvalidGrant(content)
                    || (insufficientProfilePermissions && !providerQuotaExceeded);
                var reason = "provider_error";
                if (insufficientProfilePermissions && !providerQuotaExceeded)
                    reason = "insufficient_permissions";
                else if (requiresAuthorization)
                    reason = "authorization_required";
                else if (providerQuotaExceeded)
                    reason = "provider_quota_exceeded";
                else if (response.StatusCode == HttpStatusCode.Forbidden)
                    reason = "provider_forbidden";
                throw new ProviderRequestException(reason, requiresAuthorization);
            }

            try
            {
                return JsonDocument.Parse(content);
            }
            catch (JsonException)
            {
                throw new ProviderRequestException("invalid_provider_response");
            }
        }
    }

    private string GetCallbackUrl(ProviderId provider) =>
        $"{GetPublicOrigin()!.TrimEnd('/')}/api/oauth/{provider.ToSlug()}/callback";

    private string? TryGetCallbackUrl(ProviderId provider)
    {
        var origin = GetPublicOrigin();
        return HaveCompatibleOrigins()
            ? $"{origin!.TrimEnd('/')}/api/oauth/{provider.ToSlug()}/callback"
            : null;
    }

    private string? GetPublicOrigin() =>
        configuration["RENDER_EXTERNAL_URL"] ?? configuration["App:PublicOrigin"];

    private bool HaveCompatibleOrigins()
    {
        var publicOrigin = GetPublicOrigin();
        var frontendOrigin = configuration["RENDER_EXTERNAL_URL"]
            ?? configuration["App:FrontendOrigin"]
            ?? configuration["App:PublicOrigin"];
        if (!IsSafeOrigin(publicOrigin)
            || !IsSafeOrigin(frontendOrigin)
            || !Uri.TryCreate(publicOrigin, UriKind.Absolute, out var publicUri)
            || !Uri.TryCreate(frontendOrigin, UriKind.Absolute, out var frontendUri))
        {
            return false;
        }

        var sameSchemeAndHost = string.Equals(
                publicUri.Scheme,
                frontendUri.Scheme,
                StringComparison.OrdinalIgnoreCase)
            && string.Equals(
                publicUri.IdnHost,
                frontendUri.IdnHost,
                StringComparison.OrdinalIgnoreCase);

        // The local dev proxy uses different ports on localhost; browser cookies are scoped by host, not port.
        return sameSchemeAndHost
            && (publicUri.Port == frontendUri.Port
                || (publicUri.IsLoopback && frontendUri.IsLoopback));
    }

    private static string GetAuthorizationEndpoint(ProviderId provider) => provider switch
    {
        ProviderId.Google => "https://accounts.google.com/o/oauth2/v2/auth",
        ProviderId.Github => "https://github.com/login/oauth/authorize",
        ProviderId.Discord => "https://discord.com/oauth2/authorize",
        _ => throw new ArgumentOutOfRangeException(nameof(provider))
    };

    private static string[] GetScopes(ProviderId provider) => provider switch
    {
        ProviderId.Google => ["openid", "email", "profile"],
        ProviderId.Github => ["offline_access"],
        ProviderId.Discord => ["identify"],
        _ => throw new ArgumentOutOfRangeException(nameof(provider))
    };

    private static string? GetGrantedScopeError(
        ProviderId provider,
        JsonElement tokenResponse,
        bool isAuthorizationCodeGrant)
    {
        if (!tokenResponse.TryGetProperty("scope", out var scopeValue))
        {
            // GitHub can carry earlier OAuth App permissions into a new grant. Its token
            // response must attest the effective scopes before this token is accepted.
            if (provider is ProviderId.Github or ProviderId.Discord && isAuthorizationCodeGrant)
                return "unverified_provider_scopes";

            // OAuth omits `scope` when the effective grant is unchanged. For refreshes,
            // the original authorization-code response was already checked above.
            return null;
        }
        if (scopeValue.ValueKind != JsonValueKind.String)
            return "unverified_provider_scopes";

        var allowed = provider switch
        {
            ProviderId.Google => new HashSet<string>(
                [
                    "openid",
                    "email",
                    "profile",
                    "https://www.googleapis.com/auth/userinfo.email",
                    "https://www.googleapis.com/auth/userinfo.profile"
                ],
                StringComparer.Ordinal),
            ProviderId.Github => new HashSet<string>(["offline_access"], StringComparer.Ordinal),
            ProviderId.Discord => new HashSet<string>(["identify"], StringComparer.Ordinal),
            _ => throw new ArgumentOutOfRangeException(nameof(provider))
        };

        var granted = (scopeValue.GetString() ?? string.Empty)
            .Split([' ', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (granted.Any(scope => !allowed.Contains(scope)))
            return "unexpected_provider_scopes";

        var required = provider switch
        {
            ProviderId.Google => new[] { "openid" },
            ProviderId.Github => Array.Empty<string>(),
            ProviderId.Discord => new[] { "identify" },
            _ => throw new ArgumentOutOfRangeException(nameof(provider))
        };
        if (required.Any(scope => !granted.Contains(scope, StringComparer.Ordinal))
            || (provider == ProviderId.Google
                && !granted.Contains("profile", StringComparer.Ordinal)
                && !granted.Contains("https://www.googleapis.com/auth/userinfo.profile", StringComparer.Ordinal)))
        {
            // Email is displayed only when the provider verifies and returns it; it is
            // intentionally optional for Google and is not requested from Discord.
            return "missing_required_scopes";
        }

        return null;
    }

    private static string[] GetProfileEndpoints(ProviderId provider) => provider switch
    {
        ProviderId.Google => ["https://openidconnect.googleapis.com/v1/userinfo"],
        ProviderId.Github => ["https://api.github.com/user"],
        ProviderId.Discord => ["https://discord.com/api/v10/users/@me"],
        _ => throw new ArgumentOutOfRangeException(nameof(provider))
    };

    private ProviderSettings GetSettings(ProviderId provider)
    {
        var section = provider switch
        {
            ProviderId.Google => "OAuth:Google",
            ProviderId.Github => "OAuth:Github",
            ProviderId.Discord => "OAuth:Discord",
            _ => throw new ArgumentOutOfRangeException(nameof(provider))
        };

        return new ProviderSettings(
            configuration[$"{section}:ClientId"],
            configuration[$"{section}:ClientSecret"]);
    }

    private static ProviderProfile ParseGoogleProfile(JsonElement root)
    {
        var subject = GetString(root, "sub");
        if (string.IsNullOrWhiteSpace(subject))
            throw new ProviderRequestException("invalid_provider_profile");

        var verifiedEmail = root.TryGetProperty("email_verified", out var verified)
            && verified.ValueKind == JsonValueKind.True
            ? GetString(root, "email")
            : null;

        return new ProviderProfile(
            GetString(root, "name"),
            verifiedEmail,
            verifiedEmail,
            HttpsUrl(GetString(root, "picture")),
            null)
        {
            AccountKey = subject
        };
    }

    private static IReadOnlyList<OAuthAuthorizationParameterDto> GetAuthorizationParameters(
        ProviderId provider) => provider switch
    {
        ProviderId.Google =>
        [
            new("access_type", "offline"),
            new("include_granted_scopes", "false"),
            new("prompt", "select_account consent")
        ],
        ProviderId.Github => [new("allow_signup", "false")],
        ProviderId.Discord => [new("prompt", "consent")],
        _ => throw new ArgumentOutOfRangeException(nameof(provider))
    };

    private static string GetTokenEndpoint(ProviderId provider) => provider switch
    {
        ProviderId.Google => "https://oauth2.googleapis.com/token",
        ProviderId.Github => "https://github.com/login/oauth/access_token",
        ProviderId.Discord => "https://discord.com/api/oauth2/token",
        _ => throw new ArgumentOutOfRangeException(nameof(provider))
    };

    private static ProviderProfile ParseGithubProfile(JsonElement root)
    {
        var login = GetString(root, "login");
        if (string.IsNullOrWhiteSpace(login))
            throw new ProviderRequestException("invalid_provider_profile");

        return new ProviderProfile(
            GetString(root, "name") ?? login,
            login,
            null,
            HttpsUrl(GetString(root, "avatar_url")),
            HttpsUrl(GetString(root, "html_url")))
        {
            AccountKey = root.TryGetProperty("id", out var id) ? id.ToString() : null
        };
    }

    private static ProviderProfile ParseDiscordProfile(JsonElement root)
    {
        var id = GetString(root, "id");
        var username = GetString(root, "username");
        if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(username))
            throw new ProviderRequestException("invalid_provider_profile");

        var avatarHash = GetString(root, "avatar");
        var avatarExtension = avatarHash?.StartsWith("a_", StringComparison.Ordinal) == true
            ? "gif"
            : "png";
        var avatarUrl = string.IsNullOrWhiteSpace(avatarHash)
            ? null
            : HttpsUrl(
                $"https://cdn.discordapp.com/avatars/{Uri.EscapeDataString(id)}/{Uri.EscapeDataString(avatarHash)}.{avatarExtension}");

        return new ProviderProfile(
            GetString(root, "global_name") ?? username,
            username,
            null,
            avatarUrl,
            $"https://discord.com/users/{Uri.EscapeDataString(id)}")
        {
            AccountKey = id
        };
    }

    private static string? HttpsUrl(string? value)
    {
        return Uri.TryCreate(value, UriKind.Absolute, out var uri)
            && uri.Scheme == Uri.UriSchemeHttps
            ? uri.ToString()
            : null;
    }

    private static string? GetString(JsonElement element, string property)
    {
        return element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(property, out var value)
            && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    private static int? GetInt32(JsonElement element, string property)
    {
        return element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(property, out var value)
            && value.TryGetInt32(out var number)
            ? number
            : null;
    }

    private static bool IsInvalidGrant(string content)
    {
        try
        {
            using var document = JsonDocument.Parse(content);
            var error = GetString(document.RootElement, "error");
            return string.Equals(error, "invalid_grant", StringComparison.Ordinal)
                || string.Equals(error, "bad_refresh_token", StringComparison.Ordinal);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool HasGoogleApiErrorReason(string content, params string[] expectedReasons)
    {
        try
        {
            using var document = JsonDocument.Parse(content);
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("error", out var error)
                || error.ValueKind != JsonValueKind.Object
                || !error.TryGetProperty("errors", out var errors)
                || errors.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            return errors.EnumerateArray().Any(item =>
            {
                var reason = GetString(item, "reason");
                return reason is not null
                    && expectedReasons.Contains(reason, StringComparer.Ordinal);
            });
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool HasGoogleApiErrorCode(string content, string expectedCode)
    {
        try
        {
            using var document = JsonDocument.Parse(content);
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("error", out var error)
                && error.ValueKind == JsonValueKind.String
                && string.Equals(error.GetString(), expectedCode, StringComparison.Ordinal);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool IsUsable(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && !value.Contains("replace", StringComparison.OrdinalIgnoreCase)
        && !value.Contains("your_", StringComparison.OrdinalIgnoreCase);

    private static bool IsSafeOrigin(string? value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            return false;

        return uri.PathAndQuery == "/"
            && string.IsNullOrEmpty(uri.Fragment)
            && string.IsNullOrEmpty(uri.UserInfo)
            && (uri.Scheme == Uri.UriSchemeHttps
                || (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback));
    }

    private sealed record ProviderSettings(string? ClientId, string? ClientSecret);
}
