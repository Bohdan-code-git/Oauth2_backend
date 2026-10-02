using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;

public sealed class BrowserWorkspaceStore
{
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(8);
    private static readonly TimeSpan PruneInterval = TimeSpan.FromMinutes(10);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly ConcurrentDictionary<string, WorkspaceSession> _sessions = new(StringComparer.Ordinal);
    private readonly object _creationLock = new();
    private readonly object _pruneLock = new();
    private readonly string _directory;
    private readonly IDataProtectionProvider _protectionProvider;
    private readonly ILogger<BrowserWorkspaceStore> _logger;
    private readonly TimeProvider _clock;
    private DateTimeOffset _nextPruneAt = DateTimeOffset.MinValue;

    public BrowserWorkspaceStore(
        IConfiguration configuration,
        IWebHostEnvironment environment,
        IDataProtectionProvider protectionProvider,
        ILogger<BrowserWorkspaceStore> logger,
        TimeProvider clock)
    {
        _directory = Path.GetFullPath(
            configuration["Persistence:WorkspaceDirectory"] ?? "App_Data/workspaces",
            environment.ContentRootPath);
        _protectionProvider = protectionProvider;
        _logger = logger;
        _clock = clock;
        Directory.CreateDirectory(_directory);
        SetDirectoryPermissions(_directory);
    }

    public WorkspaceSession GetOrCreate(string? browserId)
    {
        lock (_creationLock)
        {
            var now = _clock.GetUtcNow();
            PruneExpiredFilesIfDue(now);
            var id = IsValidBrowserId(browserId) ? browserId! : CreateOpaqueId();
            if (_sessions.TryGetValue(id, out var cached))
            {
                if (IsExpired(cached, now))
                {
                    Remove(id);
                    id = CreateOpaqueId();
                }
                else
                {
                    return cached;
                }
            }

            var ownerKey = OwnerKeyFor(id);
            var hadWorkspaceFile = File.Exists(WorkspacePath(ownerKey));
            WorkspaceSession? existing = null;
            var workspaceRecoveryRequired = false;
            try
            {
                existing = TryLoad(id, ownerKey, now);
            }
            catch (InvalidDataException)
            {
                workspaceRecoveryRequired = true;
                _logger.LogWarning("An unreadable browser workspace was kept and its browser session will be rotated");
            }
            if (existing is not null)
            {
                _sessions[id] = existing;
                return existing;
            }

            if (hadWorkspaceFile)
            {
                if (!workspaceRecoveryRequired)
                    DeleteWorkspaceFile(ownerKey);
                id = CreateOpaqueId();
                ownerKey = OwnerKeyFor(id);
            }

            PruneExpiredSessions(now);
            if (_sessions.Count >= 4096)
                throw new WorkspaceCapacityException();
            var created = new WorkspaceSession(id, CreateCsrfToken(), now, ownerKey);
            created.WorkspaceRecoveryRequired = workspaceRecoveryRequired;
            _sessions[id] = created;
            return created;
        }
    }

    public WorkspaceSession? Find(string? browserId)
    {
        PruneExpiredFilesIfDue(_clock.GetUtcNow());
        if (!IsValidBrowserId(browserId))
            return null;

        var now = _clock.GetUtcNow();
        if (_sessions.TryGetValue(browserId!, out var cached))
        {
            if (!IsExpired(cached, now))
                return cached;

            Remove(browserId!);
            return null;
        }

        lock (_creationLock)
        {
            if (_sessions.TryGetValue(browserId!, out cached))
            {
                if (cached.IsRevoked)
                    return null;
                if (IsExpired(cached, now))
                {
                    Remove(browserId!);
                    return null;
                }
                return cached;
            }

            var ownerKey = OwnerKeyFor(browserId!);
            WorkspaceSession? loaded;
            try
            {
                loaded = TryLoad(browserId!, ownerKey, now);
            }
            catch (InvalidDataException)
            {
                return null;
            }
            if (loaded is not null)
                _sessions[browserId!] = loaded;
            return loaded;
        }
    }

    public async Task SaveAsync(WorkspaceSession session, CancellationToken cancellationToken = default)
    {
        if (session.IsRevoked || session.OwnerKey is null || !IsValidBrowserId(session.Id)
            || !FixedEquals(session.OwnerKey, OwnerKeyFor(session.Id)))
            return;
        if (IsExpired(session, _clock.GetUtcNow()))
        {
            Remove(session.Id);
            return;
        }

        var gate = session.PersistenceLock;
        await gate.WaitAsync(cancellationToken);
        var acquiredLocks = new List<SemaphoreSlim>();
        try
        {
            if (session.IsRevoked)
                return;
            foreach (var provider in Enum.GetValues<ProviderId>())
            {
                var providerLock = session.GetProviderSyncLock(provider);
                await providerLock.WaitAsync(cancellationToken);
                acquiredLocks.Add(providerLock);
            }

            var connections = session.Connections.Values
                .Select(ToPersistedConnection)
                .OrderBy(connection => connection.Provider, StringComparer.Ordinal)
                .ToArray();
            var document = new WorkspaceDocument(1, session.CreatedAt, connections);
            var plaintext = JsonSerializer.Serialize(document, JsonOptions);
            var protectedPayload = _protectionProvider
                .CreateProtector("Switchboard.BrowserWorkspace.v1", session.OwnerKey)
                .Protect(plaintext);

            var path = WorkspacePath(session.OwnerKey);
            var temporaryPath = Path.Combine(
                _directory,
                "." + session.OwnerKey + "." + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                var payloadBytes = Encoding.UTF8.GetBytes(protectedPayload);
                await using (var output = new FileStream(
                    temporaryPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    bufferSize: 4096,
                    FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    SetFilePermissions(temporaryPath);
                    await output.WriteAsync(payloadBytes, cancellationToken);
                    await output.FlushAsync(cancellationToken);
                }

                File.Move(temporaryPath, path, overwrite: true);
                SetFilePermissions(path);
            }
            finally
            {
                if (File.Exists(temporaryPath))
                    File.Delete(temporaryPath);
            }
        }
        finally
        {
            for (var index = acquiredLocks.Count - 1; index >= 0; index--)
                acquiredLocks[index].Release();
            gate.Release();
        }
    }

    public void Remove(string browserId)
    {
        if (!IsValidBrowserId(browserId))
            return;
        lock (_creationLock)
        {
            _sessions.TryRemove(browserId, out var session);
            session?.Revoke();
            if (session is null)
            {
                DeleteWorkspaceFile(OwnerKeyFor(browserId));
                return;
            }
            var gate = session.PersistenceLock;
            gate.Wait();
            try
            {
                DeleteWorkspaceFile(OwnerKeyFor(browserId));
            }
            finally
            {
                gate.Release();
            }
        }
    }

    public static bool IsValidBrowserId(string? value)
    {
        if (value is null || value.Length != 43
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '_' or '-')))
            return false;
        try
        {
            var decoded = WebEncoders.Base64UrlDecode(value);
            return decoded.Length == 32
                && string.Equals(WebEncoders.Base64UrlEncode(decoded), value, StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static string OwnerKeyFor(string browserId) =>
        WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(browserId)));

    private WorkspaceSession? TryLoad(string browserId, string ownerKey, DateTimeOffset now)
    {
        var path = WorkspacePath(ownerKey);
        if (!File.Exists(path))
            return null;

        try
        {
            var protectedPayload = File.ReadAllText(path, Encoding.UTF8);
            var plaintext = _protectionProvider
                .CreateProtector("Switchboard.BrowserWorkspace.v1", ownerKey)
                .Unprotect(protectedPayload);
            var document = JsonSerializer.Deserialize<WorkspaceDocument>(plaintext, JsonOptions)
                ?? throw new InvalidDataException("The browser workspace document was empty.");
            if (document.Version != 1)
                throw new InvalidDataException("The browser workspace version is not supported.");
            if (document.CreatedAt.Add(SessionLifetime) <= now)
            {
                DeleteWorkspaceFile(ownerKey);
                return null;
            }

            var session = new WorkspaceSession(browserId, CreateCsrfToken(), document.CreatedAt, ownerKey);
            foreach (var item in document.Connections)
            {
                if (!Enum.GetNames<ProviderId>().Contains(item.Provider, StringComparer.OrdinalIgnoreCase)
                    || !Enum.TryParse<ProviderId>(item.Provider, ignoreCase: true, out var provider)
                    || string.IsNullOrWhiteSpace(item.AccessToken))
                    continue;

                session.Connections[provider] = new StoredProviderConnection
                {
                    Provider = provider,
                    AccessToken = item.AccessToken,
                    RefreshToken = item.RefreshToken,
                    AccessTokenExpiresAt = item.AccessTokenExpiresAt,
                    GrantedScopes = item.GrantedScopes,
                    Profile = item.Profile is { } profile
                        ? profile with { AccountKey = item.AccountKey }
                        : null,
                    ConnectedAt = item.ConnectedAt,
                    LastSyncedAt = item.LastSyncedAt,
                    Status = item.Status,
                    StatusReason = item.StatusReason,
                    SafeMessage = item.SafeMessage
                };
            }

            return session;
        }
        catch (Exception error) when (error is IOException
            or UnauthorizedAccessException
            or JsonException
            or CryptographicException
            or InvalidDataException)
        {
            _logger.LogError("Stored browser workspace could not be loaded; verify the Data Protection key ring and workspace file");
            throw new InvalidDataException("The stored browser workspace could not be read safely.", error);
        }
    }

    public void PruneExpiredFiles() => PruneExpiredFilesIfDue(_clock.GetUtcNow());

    private void PruneExpiredFilesIfDue(DateTimeOffset now)
    {
        lock (_pruneLock)
        {
            if (now < _nextPruneAt)
                return;
            _nextPruneAt = now.Add(PruneInterval);
            try
            {
                foreach (var path in Directory.EnumerateFiles(_directory, "*.dat"))
                {
                    var ownerKey = Path.GetFileNameWithoutExtension(path);
                    if (ownerKey.Length != 43)
                        continue;
                    try
                    {
                        var payload = File.ReadAllText(path, Encoding.UTF8);
                        var plaintext = _protectionProvider
                            .CreateProtector("Switchboard.BrowserWorkspace.v1", ownerKey)
                            .Unprotect(payload);
                        var document = JsonSerializer.Deserialize<WorkspaceDocument>(plaintext, JsonOptions);
                        if (document is { Version: 1 } && IsExpired(document.CreatedAt, now))
                            File.Delete(path);
                    }
                    catch (Exception error) when (error is IOException
                        or UnauthorizedAccessException
                        or JsonException
                        or CryptographicException
                        or InvalidDataException)
                    {
                        if (File.GetLastWriteTimeUtc(path).Add(SessionLifetime) <= now.UtcDateTime)
                            File.Delete(path);
                        _logger.LogWarning("A stored browser workspace could not be checked for expiry");
                    }
                }
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                _logger.LogWarning("Stored browser workspaces could not be scanned for expiry");
            }
        }
    }

    private void PruneExpiredSessions(DateTimeOffset now)
    {
        foreach (var pair in _sessions)
        {
            if (IsExpired(pair.Value, now))
                Remove(pair.Key);
        }
    }

    private void DeleteWorkspaceFile(string ownerKey)
    {
        var path = WorkspacePath(ownerKey);
        if (File.Exists(path))
            File.Delete(path);
    }

    private string WorkspacePath(string ownerKey) => Path.Combine(_directory, ownerKey + ".dat");
    private static bool IsExpired(WorkspaceSession session, DateTimeOffset now) => IsExpired(session.CreatedAt, now);
    private static bool IsExpired(DateTimeOffset createdAt, DateTimeOffset now) => createdAt.Add(SessionLifetime) <= now;

    private static bool FixedEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }

    private static PersistedConnection ToPersistedConnection(StoredProviderConnection connection) => new(
        connection.Provider.ToString(), connection.AccessToken, connection.RefreshToken,
        connection.AccessTokenExpiresAt, connection.GrantedScopes, connection.Profile,
        connection.ConnectedAt, connection.LastSyncedAt, connection.Status,
        connection.StatusReason, connection.SafeMessage, connection.Profile?.AccountKey);

    private static string CreateOpaqueId() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    private static string CreateCsrfToken() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

    private static void SetDirectoryPermissions(string path)
    {
        if (OperatingSystem.IsWindows()) return;
        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        catch (PlatformNotSupportedException)
        {
            // The host's filesystem ACLs must protect the encrypted workspace directory.
        }
    }

    private static void SetFilePermissions(string path)
    {
        if (OperatingSystem.IsWindows()) return;
        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (PlatformNotSupportedException)
        {
            // The host's filesystem ACLs must protect encrypted workspace files.
        }
    }

    private sealed record WorkspaceDocument(int Version, DateTimeOffset CreatedAt, IReadOnlyList<PersistedConnection> Connections);
    private sealed record PersistedConnection(
        string Provider, string AccessToken, string? RefreshToken, DateTimeOffset? AccessTokenExpiresAt,
        IReadOnlyList<string>? GrantedScopes, ProviderProfile? Profile,
        DateTimeOffset ConnectedAt, DateTimeOffset? LastSyncedAt, string Status, string? StatusReason,
        string? SafeMessage, string? AccountKey);
}
