public sealed class StoredProviderConnection
{
    public long SyncVersion;
    public required ProviderId Provider { get; init; }
    public required string AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public DateTimeOffset? AccessTokenExpiresAt { get; set; }
    public IReadOnlyList<string>? GrantedScopes { get; set; }
    public ProviderProfile? Profile { get; set; }
    public required DateTimeOffset ConnectedAt { get; set; }
    public DateTimeOffset? LastSyncedAt { get; set; }
    public string Status { get; set; } = "connected";
    public string? StatusReason { get; set; }
    public string? SafeMessage { get; set; }
    public StoredProviderConnection? PreviousConnection { get; set; }
}
