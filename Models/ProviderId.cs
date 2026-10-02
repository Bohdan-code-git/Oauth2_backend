public enum ProviderId
{
    Google,
    Github,
    Discord
}

public static class ProviderNames
{
    public static string ToSlug(this ProviderId provider) => provider switch
    {
        ProviderId.Google => "google",
        ProviderId.Github => "github",
        ProviderId.Discord => "discord",
        _ => throw new ArgumentOutOfRangeException(nameof(provider))
    };

    public static string ToLabel(this ProviderId provider) => provider switch
    {
        ProviderId.Google => "Google",
        ProviderId.Github => "GitHub",
        ProviderId.Discord => "Discord",
        _ => throw new ArgumentOutOfRangeException(nameof(provider))
    };

    public static bool TryParse(string? value, out ProviderId provider)
    {
        provider = default;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        return value.Trim().ToLowerInvariant() switch
        {
            "google" => Set(ProviderId.Google, out provider),
            "github" => Set(ProviderId.Github, out provider),
            "discord" => Set(ProviderId.Discord, out provider),
            _ => false
        };
    }

    private static bool Set(ProviderId value, out ProviderId provider)
    {
        provider = value;
        return true;
    }
}
