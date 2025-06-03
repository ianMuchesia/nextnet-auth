namespace AuthServer.Contracts;


public class AuthResponse
{
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string UserId { get; set; }
    public string Username { get; set; }
    public string Role { get; set; } // e.g., "Admin", "User"
}