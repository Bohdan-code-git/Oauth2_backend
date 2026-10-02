using System.Collections.Concurrent;

public sealed class WorkspaceSession
{
    private const int MaximumOAuthFeedback = OAuthStateTransactions.MaximumPendingTransactions;
    private readonly object _oauthFeedbackLock = new();
    private readonly Queue<OAuthFeedbackDto> _oauthFeedback = new();
    private int _revoked;

    public WorkspaceSession(string id, string csrfToken, DateTimeOffset createdAt, string? ownerKey = null)
    {
        Id = id;
        CsrfToken = csrfToken;
        CreatedAt = createdAt;
        OwnerKey = ownerKey;
    }

    public string Id { get; }
    public string CsrfToken { get; }
    public DateTimeOffset CreatedAt { get; }
    public string? OwnerKey { get; }
    public bool IsRevoked => Volatile.Read(ref _revoked) != 0;
    public bool WorkspaceRecoveryRequired { get; set; }
    public SemaphoreSlim PersistenceLock { get; } = new(1, 1);
    public OAuthStateTransactions PendingOAuth { get; } = new();
    public ConcurrentDictionary<ProviderId, StoredProviderConnection> Connections { get; } = new();
    public ConcurrentDictionary<ProviderId, SemaphoreSlim> ProviderSyncLocks { get; } = new();
    public ConcurrentDictionary<ProviderId, long> ProviderGenerations { get; } = new();

    public void SetOAuthFeedback(ProviderId provider, string reason)
    {
        lock (_oauthFeedbackLock)
        {
            if (_oauthFeedback.Count == MaximumOAuthFeedback)
                _oauthFeedback.Dequeue();
            _oauthFeedback.Enqueue(new OAuthFeedbackDto(provider.ToSlug(), reason));
        }
    }

    public IReadOnlyList<OAuthFeedbackDto> TakeOAuthFeedback()
    {
        lock (_oauthFeedbackLock)
        {
            var feedback = _oauthFeedback.ToArray();
            _oauthFeedback.Clear();
            return feedback;
        }
    }

    public SemaphoreSlim GetProviderSyncLock(ProviderId provider) =>
        ProviderSyncLocks.GetOrAdd(provider, static _ => new SemaphoreSlim(1, 1));

    public long GetProviderGeneration(ProviderId provider) =>
        ProviderGenerations.TryGetValue(provider, out var generation) ? generation : 0;

    public long AdvanceProviderGeneration(ProviderId provider) =>
        ProviderGenerations.AddOrUpdate(provider, 1, static (_, generation) => generation + 1);

    public void Revoke() => Interlocked.Exchange(ref _revoked, 1);
}

public sealed class InMemoryWorkspaceStore
{
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(8);
    private static readonly TimeSpan CreationWindow = TimeSpan.FromMinutes(1);
    private readonly ConcurrentDictionary<string, WorkspaceSession> _sessions = new();
    private readonly object _creationLock = new();
    private readonly TimeProvider _clock;
    private readonly int _maximumSessions;
    private readonly int _maximumNewSessionsPerMinute;
    private readonly TimeSpan _pruneInterval;
    private DateTimeOffset _nextPruneAt = DateTimeOffset.MinValue;
    private DateTimeOffset _creationWindowStartsAt = DateTimeOffset.MinValue;
    private int _createdInCurrentWindow;

    public InMemoryWorkspaceStore(
        TimeProvider clock,
        int maximumSessions = 4096,
        TimeSpan? pruneInterval = null,
        int maximumNewSessionsPerMinute = 8)
    {
        if (maximumSessions < 1)
            throw new ArgumentOutOfRangeException(nameof(maximumSessions));
        if (maximumNewSessionsPerMinute < 1)
            throw new ArgumentOutOfRangeException(nameof(maximumNewSessionsPerMinute));

        _clock = clock;
        _maximumSessions = maximumSessions;
        _pruneInterval = pruneInterval ?? TimeSpan.FromMinutes(1);
        _maximumNewSessionsPerMinute = maximumNewSessionsPerMinute;
    }

    public WorkspaceSession GetOrCreate(string? id)
    {
        var now = _clock.GetUtcNow();
        if (!string.IsNullOrWhiteSpace(id)
            && _sessions.TryGetValue(id, out var existing)
            && existing.CreatedAt.Add(SessionLifetime) > now)
        {
            return existing;
        }

        lock (_creationLock)
        {
            if (!string.IsNullOrWhiteSpace(id)
                && _sessions.TryGetValue(id, out existing)
                && existing.CreatedAt.Add(SessionLifetime) > now)
            {
                return existing;
            }

            if (_sessions.TryGetValue(id ?? string.Empty, out existing))
                _sessions.TryRemove(id ?? string.Empty, out _);

            if (now >= _nextPruneAt)
            {
                PruneExpired(now);
                _nextPruneAt = now.Add(_pruneInterval);
            }

            if (_sessions.Count >= _maximumSessions)
                throw new WorkspaceCapacityException();

            ConsumeWorkspaceCreationPermit(now);

            var created = new WorkspaceSession(CreateOpaqueId(), CreateOpaqueId(), now);
            _sessions[created.Id] = created;
            return created;
        }
    }

    public WorkspaceSession? Find(string? id)
    {
        if (string.IsNullOrWhiteSpace(id) || !_sessions.TryGetValue(id, out var session))
            return null;

        var now = _clock.GetUtcNow();
        if (session.CreatedAt.Add(SessionLifetime) <= now)
        {
            _sessions.TryRemove(id, out _);
            return null;
        }

        return session;
    }

    public void Remove(string id) => _sessions.TryRemove(id, out _);

    private void PruneExpired(DateTimeOffset now)
    {
        foreach (var pair in _sessions)
        {
            if (pair.Value.CreatedAt.Add(SessionLifetime) <= now)
            {
                pair.Value.Revoke();
                _sessions.TryRemove(pair.Key, out _);
            }
        }
    }

    private void ConsumeWorkspaceCreationPermit(DateTimeOffset now)
    {
        var windowStart = DateTimeOffset.FromUnixTimeSeconds(
            now.ToUnixTimeSeconds() / (long)CreationWindow.TotalSeconds * (long)CreationWindow.TotalSeconds);
        if (windowStart != _creationWindowStartsAt)
        {
            _creationWindowStartsAt = windowStart;
            _createdInCurrentWindow = 0;
        }

        if (_createdInCurrentWindow >= _maximumNewSessionsPerMinute)
        {
            var retryAfter = (int)Math.Max(1, Math.Ceiling(
                (windowStart.Add(CreationWindow) - now).TotalSeconds));
            throw new WorkspaceCreationRateLimitException(retryAfter);
        }

        _createdInCurrentWindow++;
    }

    private static string CreateOpaqueId() =>
        Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
}

public sealed class WorkspaceCapacityException()
    : Exception("The in-memory workspace capacity has been reached.");

public sealed class WorkspaceCreationRateLimitException(int retryAfterSeconds)
    : Exception("The process-wide workspace creation limit has been reached.")
{
    public int RetryAfterSeconds { get; } = retryAfterSeconds;
}
