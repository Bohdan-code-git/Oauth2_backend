public sealed record ProviderToken(
    string AccessToken,
    string? RefreshToken,
    DateTimeOffset? ExpiresAt,
    IReadOnlyList<string>? GrantedScopes = null);
