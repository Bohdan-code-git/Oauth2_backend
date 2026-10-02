public sealed class WorkspaceCleanupService(BrowserWorkspaceStore workspaces) : BackgroundService
{
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(10);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(CleanupInterval);
        do
        {
            workspaces.PruneExpiredFiles();
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
