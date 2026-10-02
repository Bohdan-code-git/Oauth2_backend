public sealed class ProviderRequestException(string reason, bool requiresAuthorization = false)
    : Exception(reason)
{
    public string Reason { get; } = reason;
    public bool RequiresAuthorization { get; } = requiresAuthorization;
}
