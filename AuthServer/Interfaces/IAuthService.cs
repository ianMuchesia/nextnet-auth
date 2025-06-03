using AuthServer.Contracts;

namespace AuthServer.Interfaces;


public interface IAuthService
{
    Task<AuthResponse> RegisterAsync(RegisterDto registerDto);

    Task<AuthResponse> LoginAsync(LoginDto loginDto);


    Task<AuthResponse> RefreshTokenAsync(string refreshToken);


    Task<bool> RevokeTokenAsync(string token);


    Task<bool> IsTokenRevokedAsync(string token);

    Task<AuthResponse> GetUserByIdAsync(string userId);
}