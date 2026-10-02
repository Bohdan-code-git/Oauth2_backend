using Xunit;

public sealed class WorkspaceStoreTests
{
    [Fact]
    public void StoreRejectsNewSessionsOnceTheBoundIsReached()
    {
        var clock = new AdjustableTimeProvider(new DateTimeOffset(2026, 10, 1, 12, 0, 0, TimeSpan.Zero));
        var store = new InMemoryWorkspaceStore(clock, maximumSessions: 1);

        _ = store.GetOrCreate(null);

        Assert.Throws<WorkspaceCapacityException>(() => store.GetOrCreate(null));
    }

    [Fact]
    public void StorePrunesExpiredSessionsBeforeRejectingAtCapacity()
    {
        var clock = new AdjustableTimeProvider(new DateTimeOffset(2026, 10, 1, 12, 0, 0, TimeSpan.Zero));
        var store = new InMemoryWorkspaceStore(
            clock,
            maximumSessions: 1,
            pruneInterval: TimeSpan.FromMinutes(1));
        var first = store.GetOrCreate(null);

        clock.Advance(TimeSpan.FromHours(8) + TimeSpan.FromMinutes(1));

        var second = store.GetOrCreate(null);

        Assert.NotEqual(first.Id, second.Id);
        Assert.Null(store.Find(first.Id));
    }

    [Fact]
    public void WorkspaceExpiryIsAbsoluteEvenWhenTheBrowserKeepsMakingRequests()
    {
        var clock = new AdjustableTimeProvider(new DateTimeOffset(2026, 10, 1, 12, 0, 0, TimeSpan.Zero));
        var store = new InMemoryWorkspaceStore(clock, maximumSessions: 1);
        var first = store.GetOrCreate(null);

        clock.Advance(TimeSpan.FromHours(7));
        Assert.NotNull(store.Find(first.Id));
        clock.Advance(TimeSpan.FromHours(1) + TimeSpan.FromMinutes(1));

        var next = store.GetOrCreate(null);

        Assert.NotEqual(first.Id, next.Id);
        Assert.Null(store.Find(first.Id));
    }

    [Fact]
    public void StoreLimitsNewWorkspacesAcrossAllClientsPerMinute()
    {
        var clock = new AdjustableTimeProvider(new DateTimeOffset(2026, 10, 1, 12, 0, 0, TimeSpan.Zero));
        var store = new InMemoryWorkspaceStore(
            clock,
            maximumSessions: 4,
            maximumNewSessionsPerMinute: 1);

        _ = store.GetOrCreate(null);

        Assert.Throws<WorkspaceCreationRateLimitException>(() => store.GetOrCreate(null));
        clock.Advance(TimeSpan.FromMinutes(1));
        _ = store.GetOrCreate(null);
    }

    private sealed class AdjustableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan duration) => _now = _now.Add(duration);
    }
}
