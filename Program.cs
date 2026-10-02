using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

var dataProtectionKeysPath = Path.GetFullPath(
    builder.Configuration["DataProtection:KeysPath"] ?? "App_Data/data-protection-keys",
    builder.Environment.ContentRootPath);
Directory.CreateDirectory(dataProtectionKeysPath);
if (!OperatingSystem.IsWindows())
{
    try
    {
        File.SetUnixFileMode(
            dataProtectionKeysPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
    catch (PlatformNotSupportedException)
    {
        // The host's filesystem ACLs must protect the Data Protection key ring.
    }
}

var dataProtection = builder.Services.AddDataProtection()
    .SetApplicationName("Switchboard")
    .PersistKeysToFileSystem(new DirectoryInfo(dataProtectionKeysPath));
var dataProtectionCertificatePath = builder.Configuration["DataProtection:CertificatePath"];
X509Certificate2? dataProtectionCertificate = null;
if (!string.IsNullOrWhiteSpace(dataProtectionCertificatePath))
{
    dataProtectionCertificate = new X509Certificate2(
        Path.GetFullPath(dataProtectionCertificatePath, builder.Environment.ContentRootPath),
        builder.Configuration["DataProtection:CertificatePassword"]);
    dataProtection.ProtectKeysWithCertificate(dataProtectionCertificate);
}
else if (builder.Configuration.GetValue<bool>("DataProtection:EphemeralCertificate"))
{
    using var rsa = RSA.Create(2048);
    var request = new CertificateRequest(
        "CN=Switchboard ephemeral Data Protection",
        rsa,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);
    dataProtectionCertificate = request.CreateSelfSigned(
        DateTimeOffset.UtcNow.AddMinutes(-5),
        DateTimeOffset.UtcNow.AddYears(10));
    dataProtection.ProtectKeysWithCertificate(dataProtectionCertificate);
}
else if (builder.Environment.IsProduction()
    && Enum.GetValues<ProviderId>().Any(provider =>
        !string.IsNullOrWhiteSpace(builder.Configuration[$"OAuth:{provider}:ClientId"])
        && !string.IsNullOrWhiteSpace(builder.Configuration[$"OAuth:{provider}:ClientSecret"])))
{
    throw new InvalidOperationException(
        "DataProtection:CertificatePath is required in production when provider OAuth credentials are configured.");
}

builder.Services.AddHttpClient("providers", client => client.Timeout = TimeSpan.FromSeconds(15));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<BrowserWorkspaceStore>();
builder.Services.AddHostedService<WorkspaceCleanupService>();
builder.Services.AddSingleton<WorkspaceSessionManager>();
builder.Services.AddSingleton<OAuthProviderClient>();
builder.Services.AddSingleton<ConnectionService>();
// Render's ingress provides the real visitor IP as the first X-Forwarded-For value.
// Outside Render, the header is ignored because direct requests can spoof it.
var trustRenderForwardedFor = !string.IsNullOrWhiteSpace(builder.Configuration["RENDER_EXTERNAL_URL"]);
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = (context, _) =>
    {
        var response = context.HttpContext.Response;
        response.Headers.RetryAfter = "60";
        var path = context.HttpContext.Request.Path.Value;
        if (path is not null
            && path.StartsWith("/api/connections/", StringComparison.OrdinalIgnoreCase)
            && path.EndsWith("/start", StringComparison.OrdinalIgnoreCase))
            response.Redirect("/?oauth=error&reason=rate_limited#top");
        return ValueTask.CompletedTask;
    };
    options.AddPolicy("workspace-init", context => RateLimitPartition.GetFixedWindowLimiter(
        ClientAddressPartitionKey.For(
            context.Connection.RemoteIpAddress,
            context.Request.Headers["X-Forwarded-For"].FirstOrDefault(),
            trustRenderForwardedFor),
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 12,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));
    options.AddPolicy("oauth-start", context => RateLimitPartition.GetFixedWindowLimiter(
        ClientAddressPartitionKey.For(
            context.Connection.RemoteIpAddress,
            context.Request.Headers["X-Forwarded-For"].FirstOrDefault(),
            trustRenderForwardedFor),
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 4,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));
    options.AddPolicy("profile-refresh", context => RateLimitPartition.GetFixedWindowLimiter(
        ClientAddressPartitionKey.For(
            context.Connection.RemoteIpAddress,
            context.Request.Headers["X-Forwarded-For"].FirstOrDefault(),
            trustRenderForwardedFor),
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 4,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));
});
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    foreach (var value in builder.Configuration.GetSection("ReverseProxy:KnownProxies").Get<string[]>() ?? [])
    {
        if (IPAddress.TryParse(value, out var address))
            options.KnownProxies.Add(address);
    }
});

var app = builder.Build();
if (dataProtectionCertificate is not null)
{
    app.Lifetime.ApplicationStopped.Register(dataProtectionCertificate.Dispose);
    if (builder.Configuration.GetValue<bool>("DataProtection:EphemeralCertificate"))
        app.Logger.LogWarning(
            "An in-memory Data Protection certificate is enabled; existing sessions may be lost when this instance restarts.");
}

app.UseForwardedHeaders();
app.UseExceptionHandler(error => error.Run(async context =>
{
    context.Response.StatusCode = StatusCodes.Status500InternalServerError;
    context.Response.ContentType = "application/json";
    context.Response.Headers.CacheControl = "no-store";
    await context.Response.WriteAsJsonAsync(new { error = "unexpected_error" });
}));
app.UseMiddleware<WorkspacePersistenceMiddleware>();
app.UseRouting();
app.UseRateLimiter();
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api"))
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
    }
    await next();
});
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapControllers();
app.MapFallback(async context =>
{
    if (context.Request.Path.StartsWithSegments("/api"))
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        await context.Response.WriteAsJsonAsync(new { error = "not_found" });
        return;
    }

    context.Response.ContentType = "text/html; charset=utf-8";
    var indexPath = Path.Combine(app.Environment.WebRootPath ?? "wwwroot", "index.html");
    if (!File.Exists(indexPath))
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return;
    }
    await context.Response.SendFileAsync(indexPath);
});

app.Run();

public partial class Program { }
