using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using OpenIddict.Abstractions;
using OAuthServer.Services.Interfaces;
using OAuthServer.Data;
using OAuthServer.Models;
using OAuthServer.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.AspNetCore.Mvc.Controllers;
using StackExchange.Redis;
using Microsoft.AspNetCore.HttpOverrides;
using System.Net;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OAuth;
using OpenIddict.Client.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
    // Register the entity sets needed by OpenIddict
    options.UseOpenIddict();
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Configure Redis
var redisConfiguration = builder.Configuration.GetSection("Redis").Get<string>();

// Configure token settings
var tokenConfig = builder.Configuration.GetSection("TokenConfiguration").Get<TokenConfiguration>();
if (tokenConfig == null)
{
    throw new InvalidOperationException("TokenConfiguration section is missing in appsettings.json");
}
builder.Services.AddSingleton(tokenConfig);

// Register services
builder.Services.AddScoped<IIdentityClientRoleService, IdentityClientRoleService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<ISessionService, SessionService>();
builder.Services.AddScoped<IAccountService, AccountService>();

builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis");
});

builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.None;
    options.Secure = CookieSecurePolicy.Always;
});

builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
    ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("Redis")));
builder.Services.AddScoped<IRedisSessionStore, RedisSessionStore>();

builder.Services.AddOpenIddict()
    // Register the OpenIddict core components.
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
    // Register the OpenIddict server components.
    .AddServer(options =>
    {
        // Enable the authorization and token endpoints.
        options.SetAuthorizationEndpointUris("connect/authorize")
               .SetTokenEndpointUris("connect/token");

        options.AllowPasswordFlow()
               .AllowRefreshTokenFlow();

        // Register the signing and encryption credentials.
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough();

        // Configure your scopes here (if needed)
        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles);
    })
    .AddClient(options =>
    {
        options.AllowAuthorizationCodeFlow();

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
               .EnableRedirectionEndpointPassthrough();

        options.UseSystemNetHttp();

        options.UseWebProviders()
               .AddGitHub(options =>
               {
                   options.SetClientId(builder.Configuration["GitHub:ClientId"])
                          .SetClientSecret(builder.Configuration["GitHub:ClientSecret"])
                          .SetRedirectUri("callback/login/github");
               });
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// Configure authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIddictClientAspNetCoreDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.LoginPath = "/account/login";
})
.AddJwtBearer("Bearer", options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenConfig.SecretKey)),
        ValidateIssuer = true,
        ValidIssuer = tokenConfig.Issuer,
        ValidateAudience = true,
        ValidAudience = tokenConfig.Audience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
})
.AddGoogle("Google", options =>
{
    var googleAuthSection = builder.Configuration.GetSection("Authentication:Google");
    options.ClientId = googleAuthSection["ClientId"] ?? throw new InvalidOperationException("Google ClientId is missing in configuration");
    options.ClientSecret = googleAuthSection["ClientSecret"] ?? throw new InvalidOperationException("Google ClientSecret is missing in configuration");

    options.CallbackPath = "/account/callback";
    
    options.SaveTokens = true;
    options.Events = new OAuthEvents
    {
        OnCreatingTicket = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Creating ticket for Google authentication");
            return Task.CompletedTask;
        },
        OnTicketReceived = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Successfully received authentication ticket from Google");
            return Task.CompletedTask;
        }
    };
});

// Configure CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("http://localhost:5250", "https://localhost:5251", "http://localhost:62128") // Add your client application URLs here
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

// Configure CORS for your SPA
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSPA", policy =>
    {
        policy.WithOrigins("http://localhost:3000") // Update with your SPA URL
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "OAuth Server API",
        Version = "v1",
        Description = "OAuth 2.0 Authorization Server API"
    });

    // Add JWT bearer authentication
    options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });

    options.EnableAnnotations();

    // Include XML comments
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    options.IncludeXmlComments(xmlPath);

    // Customize operation IDs
    options.CustomOperationIds(apiDesc =>
    {
        if (apiDesc.ActionDescriptor is ControllerActionDescriptor controllerActionDescriptor)
        {
            return $"{controllerActionDescriptor.ControllerName}_{controllerActionDescriptor.MethodInfo.Name}";
        }
        return null;
    });

    // Configure to handle conflicting actions
    options.ResolveConflictingActions(apiDescriptions => apiDescriptions.First());
});

// Configure Kestrel to allow HTTP and HTTPS
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(5250); // HTTP port
    options.ListenAnyIP(5251, listenOptions =>
    {
        listenOptions.UseHttps(); // HTTPS port
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Use CORS before authentication
app.UseCors("AllowSPA");

// Authentication & Authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Seed the database with the default application
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

    await context.Database.EnsureCreatedAsync();

    if (await manager.FindByClientIdAsync("postman") == null)
    {
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "postman",
            ClientSecret = "postman-secret",
            DisplayName = "Postman",
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.Password,
                Permissions.GrantTypes.RefreshToken,
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles
            }
        });
    }
}

app.Run();
