using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthServer.AppDataContext;
using AuthServer.Contracts;
using AuthServer.Interfaces;
using AuthServer.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Services;


public class AuthService : IAuthService
{

    private readonly AuthDbContext _context;

    private readonly ILogger<AuthService> _logger;

    private readonly JwtSettings _jwtSettings;

    private readonly IHttpContextAccessor _httpContextAccessor;
    public AuthService(AuthDbContext context, ILogger<AuthService> logger, JwtSettings jwtSettings, IHttpContextAccessor httpContextAccessor)
    {
        _jwtSettings = jwtSettings;

        _context = context;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }
    public Task<AuthResponse> GetUserByIdAsync(string userId)
    {
        throw new NotImplementedException();
    }

    public Task<bool> IsTokenRevokedAsync(string token)
    {
        throw new NotImplementedException();
    }

    public async Task<AuthResponse> LoginAsync(LoginDto loginDto)
    {
        //find user by username or email
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email == loginDto.Email);

        if (user == null)
        {
            _logger.LogWarning("User with  email {Email} not found.",
                 loginDto.Email);
            throw new Exception("Invalid username or password.");
        }

        //check password
        if (!BCrypt.Net.BCrypt.Verify(loginDto.Password, user.PasswordHash))
        {
            _logger.LogWarning("Invalid password for user {Username}.", user.Email);
            throw new Exception("Invalid username or password.");
        }

        //generate JWT token
        var token = GenerateJwtToken(user.Id, user.Email);
         var expiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes);

        // Set authentication cookie
        SetAuthenticationCookie(token, expiresAt);

        return new AuthResponse
        {
            AccessToken = token,
            RefreshToken = string.Empty, // Implement refresh token logic if needed
            ExpiresAt = DateTime.UtcNow.AddHours(8),
            UserId = user.Id.ToString(),
            Username = user.Username,
            Role = user.Role
        };
    }

    public Task<AuthResponse> RefreshTokenAsync(string refreshToken)
    {
        throw new NotImplementedException();
    }

    public async Task<AuthResponse> RegisterAsync(RegisterDto registerDto)
    {

        //if user exists, throw exception
        var existingUser = await _context.Users
            .FirstOrDefaultAsync(u => u.Username == registerDto.Username || u.Email == registerDto.Email);

        if (existingUser != null)
        {
            _logger.LogWarning("User with username {Username} or email {Email} already exists.",
                registerDto.Username, registerDto.Email);
            throw new Exception("User already exists.");
        }

        //hash password
        var hashedPassword = BCrypt.Net.BCrypt.HashPassword(registerDto.Password);

        //create new user
        var newUser = new User
        {
            Username = registerDto.Username,
            PasswordHash = hashedPassword,
            Email = registerDto.Email,
            Role = registerDto.Role // e.g., "Admin", "User"
        };


        //add user to database
        _context.Users.Add(newUser);

        await _context.SaveChangesAsync();

        _logger.LogInformation("User {Username} registered successfully.", registerDto.Username);

        //generate JWT token
        var token = GenerateJwtToken(newUser.Id, newUser.Email);
         var expiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes);

        // Set authentication cookie
        SetAuthenticationCookie(token, expiresAt);

        return new AuthResponse
        {
            AccessToken = token,
            RefreshToken = string.Empty, // Implement refresh token logic if needed
            ExpiresAt = DateTime.UtcNow.AddHours(8),
            UserId = newUser.Id.ToString(),
            Username = newUser.Username,
            Role = newUser.Role
        };




    }

    public Task<bool> RevokeTokenAsync(string token)
    {
        // Clear the authentication cookie
        ClearAuthenticationCookie();
        return Task.FromResult(true);
    }


    private string GenerateJwtToken(Guid userId, string email)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_jwtSettings.Secret);

        var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.Now.AddHours(8),
            Issuer = _jwtSettings.Issuer,
            Audience = _jwtSettings.Audience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public void LogoutAsync()
    {
        ClearAuthenticationCookie();
    }


    private void SetAuthenticationCookie(string token, DateTime expiresAt)
    {
        var httpContext = _httpContextAccessor.HttpContext;

        if (httpContext == null)
        {
            _logger.LogError("HttpContext is null. Cannot set authentication cookie.");
            return;
        }

        var cookieOPtions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true, // Set to false for development, true for production
            Expires = expiresAt,
            SameSite = SameSiteMode.Strict, // Adjust as needed
            Path = "/",
            IsEssential = true // Ensure the cookie is sent with every request

        };


        httpContext.Response.Cookies.Append("AuthToken", token, cookieOPtions);

        _logger.LogInformation("Authentication cookie set with expiration at {ExpiresAt}", expiresAt);
    }


    private void ClearAuthenticationCookie()
    {
        var httpContext = _httpContextAccessor.HttpContext;

        if (httpContext == null)
        {
            _logger.LogError("HttpContext is null. Cannot clear authentication cookie.");
            return;
        }

        httpContext.Response.Cookies.Delete("AuthToken");

        _logger.LogInformation("Authentication cookie cleared.");
    }
}