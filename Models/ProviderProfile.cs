using System.Text.Json.Serialization;

public sealed record ProviderProfile(
    string? DisplayName,
    string? Identifier,
    string? Email,
    string? AvatarUrl,
    string? ProfileUrl)
{
    [JsonIgnore]
    public string? AccountKey { get; init; }
}
