using System.Text;
using AuthServer.AppDataContext;
using AuthServer.Middleware;
using AuthServer.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add HttpContextAccessor for cookie operations
builder.Services.AddHttpContextAccessor();

// Configure DbSettings
builder.Services.Configure<DbSettings>(builder.Configuration.GetSection("DbSettings"));
builder.Services.AddSingleton<AuthDbContext>();

// Configure JwtSettings with proper validation
var jwtSettingsSection = builder.Configuration.GetSection("JwtSettings");
builder.Services.Configure<JwtSettings>(jwtSettingsSection);

// Get JwtSettings for authentication configuration
var jwtSettings = jwtSettingsSection.Get<JwtSettings>();

// Validate JWT settings
if (jwtSettings == null || string.IsNullOrEmpty(jwtSettings.Secret))
{
    throw new InvalidOperationException("JWT settings are not properly configured. Please check your appsettings.json file.");
}

// Register JwtSettings as a singleton for direct injection
builder.Services.AddSingleton(jwtSettings);

// Add service registrations
builder.Services.AddScoped<AuthServer.Interfaces.IUserService, AuthServer.Services.UserService>();
builder.Services.AddScoped<AuthServer.Interfaces.IAuthService, AuthServer.Services.AuthService>();

// Add exception handling
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

// Add logging
builder.Services.AddLogging();

// Configure JWT authentication (keeping for API compatibility)
var key = Encoding.UTF8.GetBytes(jwtSettings.Secret);

builder.Services.AddAuthentication(options =>
{
    // Set cookie authentication as default for web requests
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.Cookie.Name = "AuthToken";
    options.Cookie.HttpOnly = true;
   options.Cookie.SecurePolicy = builder.Environment.IsDevelopment() 
        ? CookieSecurePolicy.None 
        : CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Path = "/";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(jwtSettings.ExpirationInMinutes);
    options.SlidingExpiration = false; // Set to true if you want sliding expiration
    
    // Configure login/logout paths
    options.LoginPath = "/api/auth/login";
    options.LogoutPath = "/api/auth/logout";
    options.AccessDeniedPath = "/api/auth/access-denied";
    
    // Return JSON for API requests instead of redirects
    options.Events.OnRedirectToLogin = context =>
    {
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = 401;
            return Task.CompletedTask;
        }
        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    };
    
    options.Events.OnRedirectToAccessDenied = context =>
    {
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = 403;
            return Task.CompletedTask;
        }
        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    };
})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    // Keep JWT for API clients that prefer bearer tokens
    options.RequireHttpsMetadata = false; // Set to true in production
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidateAudience = true,
        ValidAudience = jwtSettings.Audience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(5)
    };

    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<JwtBearerEvents>>();
            logger.LogError("JWT Authentication failed: {Exception}", context.Exception);
            return Task.CompletedTask;
        }
    };
});

// Add authorization
builder.Services.AddAuthorization();

// Configure CORS if needed for frontend applications
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins("http://localhost:3000", "https://localhost:3000") // Add your frontend URLs
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials(); // Important for cookies
    });
});

var app = builder.Build();

// Initialize database context if needed
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    // Add any database initialization logic here if needed
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    
    // In development, allow HTTP cookies (remove in production)
    // app.Use(async (context, next) =>
    // {
    //     context.Response.Headers.Add("Set-Cookie", context.Response.Headers["Set-Cookie"]
    //         .ToString().Replace("Secure;", ""));
    //     await next();
    // });
}

app.UseHttpsRedirection();

// Enable CORS
app.UseCors("AllowFrontend");

// Important: Order matters here
app.UseMiddleware<JwtMiddleware>(); // This reads the JWT from cookie and sets up context
app.UseAuthentication(); // This processes the authentication schemes
app.UseMiddleware<UserContextMiddleware>(); // This loads user data from database
app.UseAuthorization(); // This handles authorization

app.MapControllers();

app.Run();