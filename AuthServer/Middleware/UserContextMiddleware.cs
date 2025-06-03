

using System.Security.Claims;
using AuthServer.Interfaces;

namespace AuthServer.Middleware;


 public class UserContextMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<UserContextMiddleware> _logger;
        
        public UserContextMiddleware(RequestDelegate next, ILogger<UserContextMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }
        
        public async Task InvokeAsync(HttpContext context, IUserService userRepository)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Only process if user is authenticated
            if (context.User?.Identity?.IsAuthenticated == true)
            {
                try 
                {
                    // Get the user ID from the 'sub' claim (which is mapped to NameIdentifier)
                    var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? 
                                 context.User.FindFirst("sub")?.Value;
                    
                    if (!string.IsNullOrEmpty(userId) && Guid.TryParse(userId, out Guid userGuid))
                    {
                        var user = await userRepository.GetUserByIdAsync(userGuid);
                        if (user != null)
                        {
                            // Store both the full user object and just the ID for convenience
                            context.Items["CurrentUser"] = user;
                            context.Items["CurrentUserId"] = userGuid;
                            _logger.LogDebug("User {UserId} loaded from database", userGuid);
                        }
                        else
                        {
                            _logger.LogWarning("User {UserId} from token not found in database", userGuid);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error loading user from database");
                }
            }
            
            await _next(context);
        }
    }