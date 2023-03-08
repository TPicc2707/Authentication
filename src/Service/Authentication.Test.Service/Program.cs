using Authentication.Test.Service;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;
using Microsoft.OpenApi.Models;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
string schemaName = "myOAuth";

builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
            .AddMicrosoftIdentityWebApp(identity =>
            {
                var instance = builder.Configuration.GetValue<string>("AzureAd:Instance");
                var tenantId = builder.Configuration.GetValue<string>("AzureAd:TenantId");
                var swaggerUiGetwayClientId = builder.Configuration.GetValue<string>("AzureAd:ClientId");
                var swaggerUiGetwaySecret = builder.Configuration.GetValue<string>("AzureAd:ClientSecret");
                var swaggerOpenIdSignInCallBack = builder.Configuration.GetValue<string>("AzureAd:CallbackPath");

                identity.CallbackPath = swaggerOpenIdSignInCallBack;
                identity.ClientId = swaggerUiGetwayClientId;
                identity.ClientSecret = swaggerUiGetwaySecret;
                identity.TenantId = tenantId;
                identity.Instance = instance;

            });

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromHours(1);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});


// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(builder =>
    builder.AllowAnyOrigin()
            .AllowAnyHeader()
            .AllowAnyMethod());
});

var app = builder.Build();

app.UseSession();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseMiddleware<SwaggerOAuthMiddleware>(builder.Configuration);
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseCors();

app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
});

app.Run();
