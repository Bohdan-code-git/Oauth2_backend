public sealed class WorkspacePersistenceMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, BrowserWorkspaceStore store)
    {
        try
        {
            await next(context);
        }
        finally
        {
            if (context.Items.TryGetValue(WorkspaceSessionManager.PersistenceItemKey, out var value)
                && value is WorkspaceSession { OwnerKey: not null } session)
            {
                await store.SaveAsync(session, CancellationToken.None);
            }
        }
    }
}
