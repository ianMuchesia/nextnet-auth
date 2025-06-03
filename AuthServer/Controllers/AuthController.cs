using AuthServer.Contracts;
using AuthServer.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : BaseApiController
{
    private readonly IAuthService _authService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IAuthService authService, ILogger<AuthController> logger)
    {
        _authService = authService;
        _logger = logger;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
    {
        try
        {
            var result = await _authService.RegisterAsync(registerDto);
            
            _logger.LogInformation("User {Username} registered successfully", registerDto.Username);
            
            // Return success response - token is already set in cookie
            return Ok(new
            {
                message = "Registration successful",
                user = new
                {
                    id = result.UserId,
                    username = result.Username,
                    role = result.Role
                },
                expiresAt = result.ExpiresAt
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Registration failed for {Username}", registerDto.Username);
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
    {
        try
        {
            var result = await _authService.LoginAsync(loginDto);
            
            _logger.LogInformation("User {Email} logged in successfully", loginDto.Email);
            
            // Return success response - token is already set in cookie
            return Ok(new
            {
                message = "Login successful",
                user = new
                {
                    id = result.UserId,
                    username = result.Username,
                    role = result.Role
                },
                expiresAt = result.ExpiresAt
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login failed for {Email}", loginDto.Email);
            return Unauthorized(new { message = ex.Message });
        }
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        try
        {
            var userId = GetUserId();
            await _authService.RevokeTokenAsync(""); // Token parameter not needed for cookie-based auth
            
            _logger.LogInformation("User {UserId} logged out successfully", userId);
            
            return Ok(new { message = "Logout successful" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Logout failed");
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpGet("profile")]
    [Authorize]
    public IActionResult GetProfile()
    {
        try
        {
            var user = GetCurrentUser();
            
            return Ok(new
            {
                id = user.Id,
                username = user.Username,
                email = user.Email,
                role = user.Role
              
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get user profile");
            return Unauthorized(new { message = "User not authenticated" });
        }
    }

    [HttpGet("check")]
    [Authorize]
    public IActionResult CheckAuthentication()
    {
        try
        {
            var userId = GetUserId();
            var email = GetUserEmail();
            
            return Ok(new
            {
                authenticated = true,
                userId = userId,
                email = email,
                message = "User is authenticated"
            });
        }
        catch (Exception ex)
        {
            return Unauthorized(new { authenticated = false, message = "User not authenticated" });
        }
    }

    [HttpPost("refresh")]
    [Authorize]
    public IActionResult RefreshToken()
    {
        try
        {
            // For cookie-based auth, we can regenerate the token and update the cookie
            var user = GetCurrentUser();
            
            // You might want to implement token refresh logic here
            // For now, returning current user info
            return Ok(new
            {
                message = "Token refreshed",
                user = new
                {
                    id = user.Id,
                    username = user.Username,
                    role = user.Role
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token refresh failed");
            return Unauthorized(new { message = "Token refresh failed" });
        }
    }
}