using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

public sealed record OAuthTransaction(
    ProviderId Provider,
    string State,
    string? CodeVerifier,
    DateTimeOffset ExpiresAt,
    long ConnectionGeneration = 0);

public sealed class OAuthStateTransactions
{
    public const int MaximumPendingTransactions = 8;
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);
    private const int MaximumKnownExpiredTransactions = 8;
    private readonly Dictionary<string, OAuthTransaction> _pending = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ExpiredOAuthTransaction> _expired = new(StringComparer.Ordinal);
    private readonly object _sync = new();

    public OAuthTransaction Create(
        ProviderId provider,
        DateTimeOffset now,
        long connectionGeneration = 0,
        bool usePkce = true)
    {
        lock (_sync)
        {
            RemoveExpired(now);
            PruneExpired(now);
            if (_pending.Count >= MaximumPendingTransactions)
            {
                var retryAfter = _pending.Values.Min(item => item.ExpiresAt).Subtract(now);
                throw new OAuthTransactionCapacityException(retryAfter);
            }

            var transaction = new OAuthTransaction(
                provider,
                WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32)),
                usePkce ? WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32)) : null,
                now.Add(Lifetime),
                connectionGeneration);

            _pending[transaction.State] = transaction;
            return transaction;
        }
    }

    public bool TryConsume(
        string? returnedState,
        ProviderId provider,
        DateTimeOffset now,
        out OAuthTransaction? transaction) =>
        TryConsume(returnedState, provider, now, out transaction, out _);

    public bool TryConsume(
        string? returnedState,
        ProviderId provider,
        DateTimeOffset now,
        out OAuthTransaction? transaction,
        out bool knownExpired)
    {
        transaction = null;
        knownExpired = false;
        if (string.IsNullOrWhiteSpace(returnedState) || returnedState.Length > 128)
            return false;

        lock (_sync)
        {
            if (_pending.TryGetValue(returnedState, out var candidate))
            {
                if (!StateMatches(returnedState, candidate.State) || candidate.Provider != provider)
                    return false;

                if (candidate.ExpiresAt <= now)
                {
                    _pending.Remove(returnedState);
                    knownExpired = true;
                    return false;
                }

                _pending.Remove(returnedState);
                transaction = candidate;
                return true;
            }

            if (!_expired.TryGetValue(returnedState, out var expired))
                return false;
            if (expired.RetainUntil <= now)
            {
                _expired.Remove(returnedState);
                return false;
            }
            if (!StateMatches(returnedState, expired.State) || expired.Provider != provider)
                return false;

            _expired.Remove(returnedState);
            knownExpired = true;
            return false;
        }
    }

    public void RemoveProvider(ProviderId provider)
    {
        lock (_sync)
        {
            foreach (var pair in _pending.Where(pair => pair.Value.Provider == provider).ToArray())
                _pending.Remove(pair.Key);
            foreach (var pair in _expired.Where(pair => pair.Value.Provider == provider).ToArray())
                _expired.Remove(pair.Key);
        }
    }

    private void RemoveExpired(DateTimeOffset now)
    {
        foreach (var pair in _pending.Where(pair => pair.Value.ExpiresAt <= now).ToArray())
        {
            _pending.Remove(pair.Key);
            RememberExpired(pair.Value, now);
        }
    }

    private void RememberExpired(OAuthTransaction transaction, DateTimeOffset now)
    {
        PruneExpired(now);
        while (_expired.Count >= MaximumKnownExpiredTransactions)
        {
            var oldest = _expired.MinBy(pair => pair.Value.RetainUntil);
            _expired.Remove(oldest.Key);
        }

        _expired[transaction.State] = new ExpiredOAuthTransaction(
            transaction.Provider,
            transaction.State,
            now.Add(Lifetime));
    }

    private void PruneExpired(DateTimeOffset now)
    {
        foreach (var pair in _expired.Where(pair => pair.Value.RetainUntil <= now).ToArray())
            _expired.Remove(pair.Key);
    }

    private static bool StateMatches(string returnedState, string expectedState) =>
        CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(returnedState),
            Encoding.UTF8.GetBytes(expectedState));

    private sealed record ExpiredOAuthTransaction(
        ProviderId Provider,
        string State,
        DateTimeOffset RetainUntil);
}

public sealed class OAuthTransactionCapacityException(TimeSpan retryAfter)
    : Exception("The workspace has reached its pending OAuth transaction limit.")
{
    public int RetryAfterSeconds { get; } = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));
}

public static class Pkce
{
    public static string CreateChallenge(string verifier)
    {
        var digest = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return WebEncoders.Base64UrlEncode(digest);
    }
}
