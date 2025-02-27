using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.Negotiate;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

// Configure Kestrel to allow client certificates
builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(https =>
    {
        https.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.AllowCertificate;
        https.AllowAnyClientCertificate();
    });
});

// Add services to the container.
builder.Services.AddAuthentication()
    .AddNegotiate()
    .AddCertificate(options =>
    {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.ValidateValidityPeriod = true;
        options.RevocationMode = X509RevocationMode.Online;
        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                var claims = new[]
                {
                    new System.Security.Claims.Claim(
                        System.Security.Claims.ClaimTypes.NameIdentifier,
                        context.ClientCertificate.Subject,
                        System.Security.Claims.ClaimValueTypes.String,
                        context.Options.ClaimsIssuer),
                };

                context.Principal = new System.Security.Claims.ClaimsPrincipal(
                    new System.Security.Claims.ClaimsIdentity(claims, context.Scheme.Name));
                context.Success();

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CertificateRequired", policy =>
    {
        policy.AuthenticationSchemes = new[] { CertificateAuthenticationDefaults.AuthenticationScheme };
        policy.RequireAuthenticatedUser();
    });


    options.AddPolicy("NegotiateRequired", policy =>
    {
        policy.AuthenticationSchemes = new[] { NegotiateDefaults.AuthenticationScheme };
        policy.RequireAuthenticatedUser();
    });

});

builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();



app.MapGet("/w", (HttpContext context) =>
{
    return context.User.Identity?.Name ?? "No username found";
})
.RequireAuthorization("NegotiateRequired");

app.MapGet("/c", (HttpContext context) =>
{
    return context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? "No certificate subject found";
})
.RequireAuthorization("CertificateRequired");

app.Run();

