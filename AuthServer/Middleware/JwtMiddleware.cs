using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthServer.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Middleware;

public class JwtMiddleware
{
    private readonly RequestDelegate _next;
    private readonly JwtSettings _jwtSettings;
    private readonly ILogger<JwtMiddleware> _logger;

    public JwtMiddleware(RequestDelegate next, IOptions<JwtSettings> jwtSettings, ILogger<JwtMiddleware> logger)
    {
        _next = next;
        _jwtSettings = jwtSettings.Value;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        var token = ExtractTokenFromRequest(context);

        if (!string.IsNullOrEmpty(token))
        {
            AttachUserToContext(context, token);
        }

        await _next(context);
    }

    private string? ExtractTokenFromRequest(HttpContext context)
    {
        // Priority 1: Check cookie first (our new primary method)
        if (context.Request.Cookies.TryGetValue("AuthToken", out var cookieToken) && 
            !string.IsNullOrEmpty(cookieToken))
        {
            _logger.LogDebug("Token found in cookie");
            return cookieToken;
        }

        // Priority 2: Fallback to Authorization header for backward compatibility
        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
        {
            _logger.LogDebug("Token found in Authorization header");
            return authHeader.Substring("Bearer ".Length).Trim();
        }

        // Priority 3: Check for token in query parameters (for specific scenarios like file downloads)
        if (context.Request.Query.TryGetValue("token", out var queryToken) && 
            !string.IsNullOrEmpty(queryToken))
        {
            _logger.LogDebug("Token found in query parameters");
            return queryToken;
        }

        return null;
    }

    private void AttachUserToContext(HttpContext context, string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtSettings.Secret);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _jwtSettings.Issuer,
                ValidateAudience = true,
                ValidAudience = _jwtSettings.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5), // Allow for slight clock skew
                RequireExpirationTime = true
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
            var jwtToken = (JwtSecurityToken)validatedToken;

            // Extract claims
            var userId = jwtToken.Claims.FirstOrDefault(x => x.Type == "sub")?.Value ??
                        jwtToken.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
            
            var email = jwtToken.Claims.FirstOrDefault(x => x.Type == "email")?.Value ??
                       jwtToken.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
            
            var role = jwtToken.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Role)?.Value;

            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("Token validation successful but no user ID found in claims");
                return;
            }

            // Create claims identity for ASP.NET Core authentication
            var claims = new List<Claim>();
            
            if (!string.IsNullOrEmpty(userId))
                claims.Add(new Claim(ClaimTypes.NameIdentifier, userId));
            
            if (!string.IsNullOrEmpty(email))
                claims.Add(new Claim(ClaimTypes.Email, email));
            
            if (!string.IsNullOrEmpty(role))
                claims.Add(new Claim(ClaimTypes.Role, role));

            // Add all original JWT claims
            claims.AddRange(jwtToken.Claims);

            var claimsIdentity = new ClaimsIdentity(claims, "jwt");
            context.User = new ClaimsPrincipal(claimsIdentity);

            // Store user info in HttpContext.Items for easy access
            context.Items["UserId"] = userId;
            context.Items["Email"] = email;
            context.Items["Role"] = role;
            context.Items["JwtToken"] = token;

            // Store user data object for convenience
            context.Items["CurrentUser"] = new
            {
                Id = userId,
                Email = email,
                Role = role
            };

            _logger.LogDebug("User {UserId} authenticated successfully via JWT token", userId);
        }
        catch (SecurityTokenExpiredException)
        {
            _logger.LogWarning("JWT token has expired");
            // Clear cookie if token is expired
            ClearExpiredAuthCookie(context);
        }
        catch (SecurityTokenValidationException ex)
        {
            _logger.LogWarning("JWT token validation failed: {Message}", ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during JWT token validation");
        }
    }

    private void ClearExpiredAuthCookie(HttpContext context)
    {
        if (context.Request.Cookies.ContainsKey("AuthToken"))
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                Expires = DateTime.UtcNow.AddDays(-1)
            };

            context.Response.Cookies.Append("AuthToken", "", cookieOptions);
            _logger.LogInformation("Expired authentication cookie cleared");
        }
    }
}