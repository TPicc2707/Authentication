using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using WebApp.AuthenticationTest.Service.Support;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var host = builder.Host;
var configuration = builder.Configuration;
var services = builder.Services;

builder.Services.AddControllers();
builder.Services.AddSingleton<IConfiguration>(builder.Configuration);

services.AddAuthentication(options =>
{
    //Sets cookie authentication scheme
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(cookie =>
{
    cookie.Cookie.Name = "keycloak.cookie";
    cookie.Cookie.MaxAge = TimeSpan.FromMinutes(60);
    cookie.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    cookie.SlidingExpiration = true;
})
.AddOpenIdConnect(options =>
{
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.Authority = configuration.GetSection("Keycloak")["ServerRealm"];
    options.ClientId = configuration.GetSection("Keycloak")["ClientId"];
    options.ClientSecret = configuration.GetSection("Keycloak")["ClientSecret"];
    options.MetadataAddress = configuration.GetSection("Keycloak")["Metadata"];
    options.RequireHttpsMetadata = false;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.Scope.Add("openid");
    options.Scope.Add("profile");

    options.SaveTokens = true;
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.NonceCookie.SameSite = SameSiteMode.Unspecified;
    options.CorrelationCookie.SameSite = SameSiteMode.Unspecified;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = "name",
        RoleClaimType = ClaimTypes.Role,
        ValidateIssuer = true
    };
});
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    IdentityModelEventSource.ShowPII = true;
    app.UseDeveloperExceptionPage();
}
else
{
    app.Use((context, next) =>
    {
        context.Request.Scheme = "https";
        return next();
    });
}

app.UseStaticFiles();
app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
});

app.Run();
