using System.Collections.Concurrent;

public sealed class ConnectionService(
    OAuthProviderClient providers,
    TimeProvider clock)
{
    public bool IsDemoMode => providers.IsDemoMode();

    public ConnectionsResponse GetSnapshot(WorkspaceSession session)
    {
        var now = clock.GetUtcNow();
        var connections = Enum.GetValues<ProviderId>()
            .Select(provider => BuildConnection(session, provider, now))
            .ToArray();

        return new ConnectionsResponse(IsDemoMode, now, connections);
    }

    public async Task<ConnectionsResponse> CompleteAuthorizationAsync(
        WorkspaceSession session,
        ProviderId provider,
        string code,
        string? codeVerifier,
        long? expectedConnectionGeneration = null,
        CancellationToken cancellationToken = default)
    {
        if (IsDemoMode || !providers.IsConfigured(provider))
            throw new ProviderRequestException("provider_not_configured");

        var connectionGeneration = expectedConnectionGeneration ?? session.GetProviderGeneration(provider);
        if (connectionGeneration != session.GetProviderGeneration(provider))
            throw new ProviderRequestException("authorization_cancelled");

        var token = await providers.ExchangeCodeAsync(
            provider,
            code,
            codeVerifier,
            cancellationToken);

        var syncLock = session.GetProviderSyncLock(provider);
        await syncLock.WaitAsync(cancellationToken);
        try
        {
            if (connectionGeneration != session.GetProviderGeneration(provider))
                throw new ProviderRequestException("authorization_cancelled");

            session.Connections.TryGetValue(provider, out var existing);
            var connection = new StoredProviderConnection
            {
                Provider = provider,
                AccessToken = token.AccessToken,
                RefreshToken = token.RefreshToken,
                AccessTokenExpiresAt = token.ExpiresAt,
                GrantedScopes = token.GrantedScopes,
                ConnectedAt = clock.GetUtcNow(),
                Profile = null,
                LastSyncedAt = null,
                PreviousConnection = string.IsNullOrWhiteSpace(token.RefreshToken)
                    ? existing?.PreviousConnection ?? existing
                    : null
            };

            session.Connections[provider] = connection;
            if (connectionGeneration != session.GetProviderGeneration(provider))
            {
                RemoveConnectionIfCurrent(session, provider, connection);
                throw new ProviderRequestException("authorization_cancelled");
            }

            if (await SyncOneCoreAsync(connection, cancellationToken))
                Interlocked.Increment(ref connection.SyncVersion);

            if (connectionGeneration != session.GetProviderGeneration(provider))
            {
                RemoveConnectionIfCurrent(session, provider, connection);
                throw new ProviderRequestException("authorization_cancelled");
            }
        }
        finally
        {
            syncLock.Release();
        }

        return GetSnapshot(session);
    }

    public async Task<ConnectionsResponse> RefreshAsync(
        WorkspaceSession session,
        CancellationToken cancellationToken = default)
    {
        if (!IsDemoMode)
        {
            foreach (var connection in session.Connections.Values.ToArray())
            {
                if (connection.Status == "connected")
                    await SyncOneAsync(session, connection, cancellationToken);
            }
        }

        return GetSnapshot(session);
    }

    public async Task<ConnectionsResponse> RefreshProviderAsync(
        WorkspaceSession session,
        ProviderId provider,
        CancellationToken cancellationToken = default)
    {
        if (!IsDemoMode
            && session.Connections.TryGetValue(provider, out var connection)
            && connection.Status == "connected")
        {
            await SyncOneAsync(session, connection, cancellationToken);
        }

        return GetSnapshot(session);
    }

    public void Disconnect(WorkspaceSession session, ProviderId provider)
    {
        session.AdvanceProviderGeneration(provider);
        session.PendingOAuth.RemoveProvider(provider);
        session.Connections.TryRemove(provider, out _);
    }

    private static void RemoveConnectionIfCurrent(
        WorkspaceSession session,
        ProviderId provider,
        StoredProviderConnection connection)
    {
        if (session.Connections.TryGetValue(provider, out var current)
            && ReferenceEquals(current, connection))
            session.Connections.TryRemove(provider, out _);
    }

    private ConnectionDto BuildConnection(
        WorkspaceSession session,
        ProviderId provider,
        DateTimeOffset now)
    {
        var configured = providers.IsConfigured(provider);

        if (session.Connections.TryGetValue(provider, out var connection))
        {
            return new ConnectionDto(
                provider.ToSlug(),
                provider.ToLabel(),
                connection.Status,
                configured,
                connection.Profile,
                connection.ConnectedAt,
                connection.LastSyncedAt,
                connection.SafeMessage)
            {
                AccessTokenExpiresAt = connection.AccessTokenExpiresAt,
                CanRefreshAccessToken = !string.IsNullOrWhiteSpace(connection.RefreshToken),
                GrantedScopes = connection.GrantedScopes
            };
        }

        if (IsDemoMode)
            return BuildDemoConnection(provider, configured);

        if (!configured)
        {
            return new ConnectionDto(
                provider.ToSlug(),
                provider.ToLabel(),
                "not_configured",
                false,
                null,
                null,
                null,
                "Add this provider's credentials to enable a live connection.");
        }

        return new ConnectionDto(
            provider.ToSlug(),
            provider.ToLabel(),
            "not_connected",
            true,
            null,
            null,
            null,
            null);
    }

    private static ConnectionDto BuildDemoConnection(
        ProviderId provider,
        bool configured)
    {
        return new ConnectionDto(
            provider.ToSlug(),
            provider.ToLabel(),
            configured ? "not_connected" : "not_configured",
            configured,
            null,
            null,
            null,
            configured ? null : "Add this provider's credentials to enable a live connection.");
    }

    private async Task SyncOneAsync(
        WorkspaceSession session,
        StoredProviderConnection connection,
        CancellationToken cancellationToken)
    {
        var observedVersion = Volatile.Read(ref connection.SyncVersion);
        var syncLock = session.GetProviderSyncLock(connection.Provider);
        await syncLock.WaitAsync(cancellationToken);
        try
        {
            if (!session.Connections.TryGetValue(connection.Provider, out var current)
                || !ReferenceEquals(current, connection))
                return;

            // A parallel refresh may have rotated a single-use refresh token and
            // fetched the profile while this request waited for the provider lock.
            if (observedVersion != Volatile.Read(ref connection.SyncVersion))
                return;

            if (await SyncOneCoreAsync(connection, cancellationToken))
                Interlocked.Increment(ref connection.SyncVersion);
        }
        finally
        {
            syncLock.Release();
        }
    }

    private async Task<bool> SyncOneCoreAsync(
        StoredProviderConnection connection,
        CancellationToken cancellationToken)
    {
        if (IsAccessTokenExpired(connection))
        {
            if (string.IsNullOrWhiteSpace(connection.RefreshToken))
            {
                SetAuthorizationRequired(connection);
                return true;
            }

            if (!await TryRefreshTokenAsync(connection, cancellationToken))
                return connection.Status == "reauth_required";
        }

        try
        {
            CompleteProfileSync(
                connection,
                await FetchProfileAsync(connection, cancellationToken));
            return true;
        }
        catch (ProviderRequestException error) when (error.RequiresAuthorization)
        {
            if (!string.IsNullOrWhiteSpace(connection.RefreshToken))
            {
                if (!await TryRefreshTokenAsync(connection, cancellationToken))
                    return connection.Status == "reauth_required";

                return await RetryProfileAfterRefreshAsync(connection, cancellationToken);
            }

            SetAuthorizationRequired(connection, error.Reason);
            return true;
        }
        catch (ProviderRequestException)
        {
            connection.SafeMessage = "The profile could not be refreshed just now. Try again in a moment.";
            return false;
        }
    }

    private async Task<bool> TryRefreshTokenAsync(
        StoredProviderConnection connection,
        CancellationToken cancellationToken)
    {
        try
        {
            var refreshed = await providers.RefreshAsync(
                connection.Provider,
                connection.RefreshToken!,
                cancellationToken);
            connection.AccessToken = refreshed.AccessToken;
            connection.RefreshToken = refreshed.RefreshToken ?? connection.RefreshToken;
            connection.AccessTokenExpiresAt = refreshed.ExpiresAt;
            if (refreshed.GrantedScopes is { Count: > 0 }
                || connection.GrantedScopes is null or { Count: 0 })
                connection.GrantedScopes = refreshed.GrantedScopes ?? connection.GrantedScopes;
            return true;
        }
        catch (ProviderRequestException error) when (error.RequiresAuthorization)
        {
            SetAuthorizationRequired(connection, error.Reason);
            return false;
        }
        catch (ProviderRequestException)
        {
            connection.SafeMessage = "The access token could not be refreshed. Retry, or reconnect if this keeps happening.";
            return false;
        }
    }

    private async Task<bool> RetryProfileAfterRefreshAsync(
        StoredProviderConnection connection,
        CancellationToken cancellationToken)
    {
        try
        {
            CompleteProfileSync(
                connection,
                await FetchProfileAsync(connection, cancellationToken));
            return true;
        }
        catch (ProviderRequestException error) when (error.RequiresAuthorization)
        {
            SetAuthorizationRequired(connection, error.Reason);
            return true;
        }
        catch (ProviderRequestException)
        {
            connection.SafeMessage = "The profile could not be refreshed just now. Try again in a moment.";
            return false;
        }
    }

    private bool IsAccessTokenExpired(StoredProviderConnection connection) =>
        connection.AccessTokenExpiresAt is { } expiresAt
        && expiresAt <= clock.GetUtcNow().AddSeconds(30);

    private void CompleteProfileSync(
        StoredProviderConnection connection,
        ProviderProfile? profile)
    {
        connection.Profile = profile;
        connection.LastSyncedAt = clock.GetUtcNow();
        connection.Status = "connected";
        connection.StatusReason = null;
        connection.SafeMessage = null;

        if (connection.PreviousConnection is { } previous)
        {
            var previousAccountKey = previous.Profile?.AccountKey;
            var currentAccountKey = profile?.AccountKey;
            if (!string.IsNullOrWhiteSpace(previousAccountKey)
                && !string.IsNullOrWhiteSpace(currentAccountKey)
                && SameProviderAccount(connection.Provider, previousAccountKey, currentAccountKey))
            {
                connection.ConnectedAt = previous.ConnectedAt;
                if (previous.Status != "reauth_required"
                    && string.IsNullOrWhiteSpace(connection.RefreshToken))
                    connection.RefreshToken = previous.RefreshToken;
            }

            connection.PreviousConnection = null;
        }

        if (connection.AccessTokenExpiresAt is not null
            && string.IsNullOrWhiteSpace(connection.RefreshToken))
        {
            SetAuthorizationRequired(connection, "missing_refresh_token");
        }
    }

    private async Task<ProviderProfile?> FetchProfileAsync(
        StoredProviderConnection connection,
        CancellationToken cancellationToken)
        => await providers.GetProfileAsync(
            connection.Provider,
            connection.AccessToken,
            cancellationToken);

    private static void SetAuthorizationRequired(
        StoredProviderConnection connection,
        string reason = "authorization_required")
    {
        connection.Status = "reauth_required";
        connection.StatusReason = reason;
        connection.SafeMessage = reason switch
        {
            "missing_refresh_token" => "The provider returned a short-lived access token without a refresh token. Reconnect this account when the token expires.",
            "unexpected_provider_scopes" => "The refreshed token includes permissions outside the profile-only contract. Revoke the provider grant, then reconnect with a dedicated OAuth client.",
            "missing_required_scopes" => "The provider no longer grants a required profile permission. Review and approve the requested read-only scopes to reconnect.",
            "insufficient_permissions" => "The provider says this grant lacks profile access. Reauthorize with the requested read-only scopes.",
            "unverified_provider_scopes" => "The provider did not disclose the effective scopes. Revoke old OAuth App grants or use a dedicated OAuth client before reconnecting.",
            _ => "Reconnect this account to continue refreshing its profile."
        };
    }

    private static bool SameProviderAccount(
        ProviderId provider,
        string existingIdentifier,
        string newIdentifier) =>
        string.Equals(
            existingIdentifier,
            newIdentifier,
            provider == ProviderId.Github
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal);
}
