


using AuthServer.AppDataContext;
using AuthServer.Interfaces;
using AuthServer.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Services;



public class UserService : IUserService
{

    private readonly AuthDbContext _context;

    private readonly ILogger<UserService> _logger;

    public UserService(AuthDbContext context, ILogger<UserService> logger)
    {
        _context = context;
        _logger = logger;
    }


    public Task<bool> CreateUserAsync(User user, string password)
    {
        throw new NotImplementedException();
    }

    public Task<bool> DeleteUserAsync(string userId)
    {
        throw new NotImplementedException();
    }

    public Task<User?> GetUserByEmailAsync(string email)
    {
        throw new NotImplementedException();
    }

    public async Task<User?> GetUserByIdAsync(Guid userId)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id == userId);

        return user;

    }

    public Task<bool> UpdateUserAsync(User user)
    {
        throw new NotImplementedException();
    }
}