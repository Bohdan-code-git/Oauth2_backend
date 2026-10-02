using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.AspNetCore.WebUtilities;
using Xunit;

public sealed class BrowserWorkspaceStoreTests
{
    [Fact]
    public async Task CookieWorkspaceIsEncryptedIsolatedAndRestoredAfterAStoreRestart()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "test-artifacts", Guid.NewGuid().ToString("N"));
        var keys = Path.Combine(root, "keys");
        var workspaces = Path.Combine(root, "workspaces");
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(keys);
        var protection = DataProtectionProvider.Create(new DirectoryInfo(keys));
        var config = Configuration(workspaces);
        var clock = new AdjustableTimeProvider(new DateTimeOffset(2026, 10, 1, 12, 0, 0, TimeSpan.Zero));
        var browserA = NewSessionId();
        var browserB = NewSessionId();
        const string accessToken = "access-token-must-not-appear-in-plaintext";
        const string refreshToken = "refresh-token-must-not-appear-in-plaintext";
        const string accountKey = "stable-provider-account-id";

        try
        {
            var firstStore = CreateStore(config, root, protection, clock);
            var workspace = firstStore.GetOrCreate(browserA);
            workspace.Connections[ProviderId.Github] = new StoredProviderConnection
            {
                Provider = ProviderId.Github,
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                AccessTokenExpiresAt = clock.GetUtcNow().AddHours(1),
                GrantedScopes = ["offline_access"],
                ConnectedAt = clock.GetUtcNow(),
                Profile = new ProviderProfile("Developer", "developer", null, null, null)
                {
                    AccountKey = accountKey
                }
            };
            await firstStore.SaveAsync(workspace);

            var savedFile = Assert.Single(Directory.GetFiles(workspaces, "*.dat"));
            var encryptedFile = await File.ReadAllTextAsync(savedFile);
            Assert.DoesNotContain(accessToken, encryptedFile, StringComparison.Ordinal);
            Assert.DoesNotContain(refreshToken, encryptedFile, StringComparison.Ordinal);
            Assert.DoesNotContain(browserA, Path.GetFileName(savedFile), StringComparison.Ordinal);

            var restartedStore = CreateStore(config, root, protection, clock);
            var restored = restartedStore.Find(browserA);
            Assert.NotNull(restored);
            Assert.Equal("developer", restored!.Connections[ProviderId.Github].Profile?.Identifier);
            Assert.Equal(accountKey, restored.Connections[ProviderId.Github].Profile?.AccountKey);
            Assert.DoesNotContain(
                "accountKey",
                System.Text.Json.JsonSerializer.Serialize(restored.Connections[ProviderId.Github].Profile),
                StringComparison.OrdinalIgnoreCase);
            Assert.Equal(accessToken, restored.Connections[ProviderId.Github].AccessToken);
            Assert.Equal(refreshToken, restored.Connections[ProviderId.Github].RefreshToken);
            Assert.Equal(clock.GetUtcNow().AddHours(1), restored.Connections[ProviderId.Github].AccessTokenExpiresAt);
            Assert.Equal(new[] { "offline_access" }, restored.Connections[ProviderId.Github].GrantedScopes);
            Assert.Null(restartedStore.Find(browserB));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void WorkspaceRestoreSkipsRetiredAndNumericProviderValuesInsteadOfTreatingThemAsDiscord()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "test-artifacts", Guid.NewGuid().ToString("N"));
        var keys = Path.Combine(root, "keys");
        var workspaces = Path.Combine(root, "workspaces");
        Directory.CreateDirectory(keys);
        Directory.CreateDirectory(workspaces);
        var protection = DataProtectionProvider.Create(new DirectoryInfo(keys));
        var browserId = NewSessionId();
        var ownerKey = BrowserWorkspaceStore.OwnerKeyFor(browserId);
        var timestamp = DateTimeOffset.UtcNow;
        var document = System.Text.Json.JsonSerializer.Serialize(new
        {
            version = 1,
            createdAt = timestamp,
            connections = new[]
            {
                PersistedConnection("Youtube", "retired-youtube-token"),
                PersistedConnection("2", "numeric-provider-token"),
                PersistedConnection("Discord", "discord-token")
            }
        });
        var protectedDocument = protection
            .CreateProtector("Switchboard.BrowserWorkspace.v1", ownerKey)
            .Protect(document);
        File.WriteAllText(Path.Combine(workspaces, ownerKey + ".dat"), protectedDocument);

        try
        {
            var store = CreateStore(Configuration(workspaces), root, protection, TimeProvider.System);

            var restored = store.Find(browserId);

            Assert.NotNull(restored);
            var discord = Assert.Single(restored!.Connections);
            Assert.Equal(ProviderId.Discord, discord.Key);
            Assert.Equal("discord-token", discord.Value.AccessToken);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static object PersistedConnection(string provider, string accessToken) => new
    {
        provider,
        accessToken,
        refreshToken = (string?)null,
        accessTokenExpiresAt = (DateTimeOffset?)null,
        grantedScopes = Array.Empty<string>(),
        profile = (ProviderProfile?)null,
        connectedAt = DateTimeOffset.UtcNow,
        lastSyncedAt = (DateTimeOffset?)null,
        status = "connected",
        statusReason = (string?)null,
        safeMessage = (string?)null
    };

    [Fact]
    public async Task ExpiredWorkspaceIsRemovedAndTheBrowserGetsANewOpaqueId()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "test-artifacts", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var keyDirectory = Path.Combine(root, "keys");
        Directory.CreateDirectory(keyDirectory);
        var protection = DataProtectionProvider.Create(new DirectoryInfo(keyDirectory));
        var config = Configuration(Path.Combine(root, "workspaces"));
        var clock = new AdjustableTimeProvider(new DateTimeOffset(2026, 10, 1, 12, 0, 0, TimeSpan.Zero));
        var oldId = NewSessionId();

        try
        {
            var store = CreateStore(config, root, protection, clock);
            var oldWorkspace = store.GetOrCreate(oldId);
            await store.SaveAsync(oldWorkspace);
            clock.Advance(TimeSpan.FromHours(8) + TimeSpan.FromSeconds(1));

            var newWorkspace = store.GetOrCreate(oldId);
            await store.SaveAsync(newWorkspace);

            Assert.NotEqual(oldId, newWorkspace.Id);
            Assert.Null(store.Find(oldId));
            Assert.Single(Directory.GetFiles(Path.Combine(root, "workspaces"), "*.dat"));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void UnreadableWorkspaceRotatesTheCookieWithoutOverwritingTheSavedFile()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "test-artifacts", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var keyDirectory = Path.Combine(root, "keys");
        var workspaces = Path.Combine(root, "workspaces");
        Directory.CreateDirectory(keyDirectory);
        var protection = DataProtectionProvider.Create(new DirectoryInfo(keyDirectory));
        var store = CreateStore(Configuration(workspaces), root, protection, TimeProvider.System);
        var oldId = NewSessionId();
        var oldFile = Path.Combine(workspaces, BrowserWorkspaceStore.OwnerKeyFor(oldId) + ".dat");
        const string unreadablePayload = "preserve-unreadable-workspace-for-recovery";
        Directory.CreateDirectory(workspaces);
        File.WriteAllText(oldFile, unreadablePayload);

        try
        {
            var recovered = store.GetOrCreate(oldId);

            Assert.NotEqual(oldId, recovered.Id);
            Assert.True(recovered.WorkspaceRecoveryRequired);
            Assert.Equal(unreadablePayload, File.ReadAllText(oldFile));
            Assert.Same(recovered, store.GetOrCreate(recovered.Id));
            Assert.Null(store.Find(oldId));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PeriodicCleanupRemovesExpiredWorkspaceFilesThatAreNotInMemory()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "test-artifacts", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var keyDirectory = Path.Combine(root, "keys");
        Directory.CreateDirectory(keyDirectory);
        var protection = DataProtectionProvider.Create(new DirectoryInfo(keyDirectory));
        var config = Configuration(Path.Combine(root, "workspaces"));
        var clock = new AdjustableTimeProvider(new DateTimeOffset(2026, 10, 1, 12, 0, 0, TimeSpan.Zero));

        try
        {
            var store = CreateStore(config, root, protection, clock);
            await store.SaveAsync(store.GetOrCreate(NewSessionId()));
            Assert.Single(Directory.GetFiles(Path.Combine(root, "workspaces"), "*.dat"));

            clock.Advance(TimeSpan.FromHours(8) + TimeSpan.FromSeconds(1));
            var restartedStore = CreateStore(config, root, protection, clock);
            restartedStore.PruneExpiredFiles();

            Assert.Empty(Directory.GetFiles(Path.Combine(root, "workspaces"), "*.dat"));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void InvalidBrowserIdsCannotBeResolvedOrUsedAsWorkspaceFileNames()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "test-artifacts", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var keyDirectory = Path.Combine(root, "keys");
        Directory.CreateDirectory(keyDirectory);
        var protection = DataProtectionProvider.Create(new DirectoryInfo(keyDirectory));
        var config = Configuration(Path.Combine(root, "workspaces"));

        try
        {
            var store = CreateStore(config, root, protection, TimeProvider.System);

            Assert.Null(store.Find("../../outside"));
            var workspace = store.GetOrCreate("../../outside");

            Assert.NotEqual("../../outside", workspace.Id);
            Assert.Matches("^[A-Za-z0-9_-]{43}$", workspace.Id);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RemovingAWorkspaceWaitsForQueuedSaveAndPreventsItFromRestoringTokens()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "test-artifacts", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var keyDirectory = Path.Combine(root, "keys");
        Directory.CreateDirectory(keyDirectory);
        var protection = DataProtectionProvider.Create(new DirectoryInfo(keyDirectory));
        var config = Configuration(Path.Combine(root, "workspaces"));

        try
        {
            var store = CreateStore(config, root, protection, TimeProvider.System);
            var workspace = store.GetOrCreate(NewSessionId());
            workspace.Connections[ProviderId.Google] = new StoredProviderConnection
            {
                Provider = ProviderId.Google,
                AccessToken = "private-access-token",
                ConnectedAt = DateTimeOffset.UtcNow
            };
            await store.SaveAsync(workspace);

            await workspace.PersistenceLock.WaitAsync();
            var queuedSave = Task.Run(() => store.SaveAsync(workspace));
            var remove = Task.Run(() => store.Remove(workspace.Id));
            try
            {
                Assert.True(SpinWait.SpinUntil(() => workspace.IsRevoked, TimeSpan.FromSeconds(5)));
            }
            finally
            {
                workspace.PersistenceLock.Release();
            }

            await Task.WhenAll(queuedSave, remove);
            await store.SaveAsync(workspace);

            Assert.True(workspace.IsRevoked);
            Assert.Null(store.Find(workspace.Id));
            Assert.Empty(Directory.GetFiles(Path.Combine(root, "workspaces"), "*.dat"));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void CsrfTokenBelongsToOneBrowserCookie()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "test-artifacts", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var keyDirectory = Path.Combine(root, "keys");
        Directory.CreateDirectory(keyDirectory);
        var protection = DataProtectionProvider.Create(new DirectoryInfo(keyDirectory));
        var config = Configuration(Path.Combine(root, "workspaces"));

        try
        {
            var store = CreateStore(config, root, protection, TimeProvider.System);
            var manager = new WorkspaceSessionManager(store, new TestEnvironment(root) { EnvironmentName = "Development" });
            var contextA = new Microsoft.AspNetCore.Http.DefaultHttpContext();
            var sessionA = manager.GetOrCreate(contextA);
            contextA.Request.Headers.Cookie = contextA.Response.Headers.SetCookie.ToString().Split(';')[0];
            contextA.Request.Headers[WorkspaceSessionManager.CsrfHeaderName] = sessionA.CsrfToken;
            Assert.True(manager.HasValidCsrfToken(contextA.Request, sessionA));

            var contextB = new Microsoft.AspNetCore.Http.DefaultHttpContext();
            var sessionB = manager.GetOrCreate(contextB);
            contextB.Request.Headers.Cookie = contextB.Response.Headers.SetCookie.ToString().Split(';')[0];
            contextB.Request.Headers[WorkspaceSessionManager.CsrfHeaderName] = sessionA.CsrfToken;
            Assert.False(manager.HasValidCsrfToken(contextB.Request, sessionB));
            contextB.Request.Headers[WorkspaceSessionManager.CsrfHeaderName] = sessionB.CsrfToken;
            Assert.True(manager.HasValidCsrfToken(contextB.Request, sessionB));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static IConfiguration Configuration(string directory) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Persistence:WorkspaceDirectory"] = directory
        })
        .Build();

    private static BrowserWorkspaceStore CreateStore(
        IConfiguration configuration,
        string root,
        IDataProtectionProvider protection,
        TimeProvider clock) => new(
            configuration,
            new TestEnvironment(root),
            protection,
            NullLogger<BrowserWorkspaceStore>.Instance,
            clock);

    private static string NewSessionId() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

    private sealed class AdjustableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now = _now.Add(duration);
    }

    private sealed class TestEnvironment(string root) : IWebHostEnvironment
    {
        public string ApplicationName { get; set; } = "Switchboard.Tests";
        public string WebRootPath { get; set; } = root;
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string EnvironmentName { get; set; } = "Testing";
        public string ContentRootPath { get; set; } = root;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
