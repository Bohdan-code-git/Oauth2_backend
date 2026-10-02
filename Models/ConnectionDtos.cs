public sealed record ConnectionDto(
    string Provider,
    string Label,
    string Status,
    bool Configured,
    ProviderProfile? Profile,
    DateTimeOffset? ConnectedAt,
    DateTimeOffset? LastSyncedAt,
    string? Message)
{
    public DateTimeOffset? AccessTokenExpiresAt { get; init; }
    public bool CanRefreshAccessToken { get; init; }
    public IReadOnlyList<string>? GrantedScopes { get; init; }
}

public sealed record ConnectionsResponse(
    bool DemoMode,
    DateTimeOffset GeneratedAt,
    IReadOnlyList<ConnectionDto> Connections,
    IReadOnlyList<OAuthFeedbackDto>? OAuthFeedback = null);

public sealed record OAuthFeedbackDto(string Provider, string Reason);

public sealed record SessionResponse(
    string Application,
    string AccessMode,
    string Mode,
    string CsrfToken,
    bool WorkspaceRecoveryRequired = false);

public sealed record OAuthProviderInfoDto(
    string Provider,
    string Label,
    bool Configured,
    string AuthorizationEndpoint,
    string TokenEndpoint,
    string? CallbackUri,
    string ResponseType,
    IReadOnlyList<string> Scopes,
    string? PkceMethod,
    IReadOnlyList<string> ProfileEndpoints,
    IReadOnlyList<OAuthAuthorizationParameterDto> AuthorizationParameters);

public sealed record OAuthAuthorizationParameterDto(string Name, string Value);

public sealed record OAuthProvidersResponse(
    bool DemoMode,
    IReadOnlyList<OAuthProviderInfoDto> Providers);
