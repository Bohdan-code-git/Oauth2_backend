using System.Security.Cryptography;
using System.Text;

public sealed class WorkspaceSessionManager
{
    public const string CsrfHeaderName = "X-CSRF-Token";
    public const string PersistenceItemKey = "switchboard.browser-workspace";
    private readonly BrowserWorkspaceStore? _persistentStore;
    private readonly InMemoryWorkspaceStore? _testStore;
    private readonly IWebHostEnvironment _environment;
    private readonly bool _testOnlyAnonymousMode;

    public WorkspaceSessionManager(
        BrowserWorkspaceStore persistentStore,
        IWebHostEnvironment environment)
    {
        _persistentStore = persistentStore;
        _environment = environment;
    }

    // Controller unit tests use an in-memory store; the web host always uses the encrypted store.
    internal WorkspaceSessionManager(InMemoryWorkspaceStore testStore, IWebHostEnvironment environment)
    {
        _testStore = testStore;
        _environment = environment;
        _testOnlyAnonymousMode = true;
    }

    private string CookieName => _environment.IsDevelopment()
        ? "switchboard.sid"
        : "__Host-switchboard.sid";

    public WorkspaceSession GetOrCreate(HttpContext context)
    {
        var cookieId = ReadValidCookieId(context);
        var session = _testOnlyAnonymousMode
            ? _testStore!.GetOrCreate(cookieId)
            : _persistentStore!.GetOrCreate(cookieId);

        if (!string.Equals(cookieId, session.Id, StringComparison.Ordinal))
            context.Response.Cookies.Append(CookieName, session.Id, CookieOptions());
        context.Items[PersistenceItemKey] = session;
        return session;
    }

    public WorkspaceSession? Find(HttpContext context)
    {
        var cookieId = ReadValidCookieId(context);
        if (cookieId is null)
            return null;

        var session = _testOnlyAnonymousMode
            ? _testStore!.Find(cookieId)
            : _persistentStore!.Find(cookieId);
        if (session is not null)
            context.Items[PersistenceItemKey] = session;
        return session;
    }

    public bool HasValidCsrfToken(HttpRequest request, WorkspaceSession? session)
    {
        return IsValidCsrfToken(request, session, request.Headers[CsrfHeaderName].FirstOrDefault());
    }

    public bool HasValidCsrfFormToken(
        HttpRequest request,
        WorkspaceSession? session,
        string? formToken)
    {
        var supplied = request.Headers[CsrfHeaderName].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(supplied))
            supplied = formToken;
        return IsValidCsrfToken(request, session, supplied);
    }

    public void ClearWorkspace(HttpContext context, WorkspaceSession session)
    {
        if (_testOnlyAnonymousMode)
            _testStore!.Remove(session.Id);
        else
            _persistentStore!.Remove(session.Id);

        context.Items.Remove(PersistenceItemKey);

        context.Response.Cookies.Delete(CookieName, new CookieOptions
        {
            Path = "/",
            Secure = !_environment.IsDevelopment(),
            SameSite = SameSiteMode.Lax,
            HttpOnly = true,
            IsEssential = true
        });
    }

    private string? ReadValidCookieId(HttpContext context)
    {
        var value = context.Request.Cookies[CookieName];
        if (string.IsNullOrWhiteSpace(value))
            return null;
        return _testOnlyAnonymousMode || BrowserWorkspaceStore.IsValidBrowserId(value)
            ? value
            : null;
    }

    private bool IsValidCsrfToken(HttpRequest request, WorkspaceSession? session, string? supplied)
    {
        if (session is null
            || session.IsRevoked
            || !string.Equals(ReadValidCookieId(request.HttpContext), session.Id, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(supplied))
            return false;

        var suppliedBytes = Encoding.UTF8.GetBytes(supplied);
        var expectedBytes = Encoding.UTF8.GetBytes(session.CsrfToken);
        return suppliedBytes.Length == expectedBytes.Length
            && CryptographicOperations.FixedTimeEquals(suppliedBytes, expectedBytes);
    }

    private CookieOptions CookieOptions() => new()
    {
        HttpOnly = true,
        Secure = !_environment.IsDevelopment(),
        SameSite = SameSiteMode.Lax,
        Path = "/",
        IsEssential = true,
        MaxAge = TimeSpan.FromHours(8)
    };
}
