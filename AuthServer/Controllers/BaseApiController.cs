using System;
using System.Security.Claims;
using AuthServer.Models;
using Microsoft.AspNetCore.Mvc;


namespace AuthServer.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public abstract class BaseApiController : ControllerBase
    {
        /// <summary>
        /// Gets the current user's ID from the request context.
        /// Throws UnauthorizedException if the user ID cannot be found.
        /// </summary>
        protected Guid GetUserId()
        {
            // Try multiple sources in order of preference:
            // 1. From HttpContext.Items (set by UserContextMiddleware)
            // 2. From the JWT "sub" claim (standard JWT claim)
            // 3. From the ClaimTypes.NameIdentifier claim (ASP.NET mapping)

            // Try to get from middleware first
            if (HttpContext.Items.TryGetValue("CurrentUserId", out var userIdObj) &&
                userIdObj is Guid userId)
            {
                return userId;
            }

            // Try to get from HttpContext.Items as string
            if (HttpContext.Items.TryGetValue("UserId", out var userIdStrObj) &&
                userIdStrObj is string userIdStr &&
                Guid.TryParse(userIdStr, out var userGuidFromStr))
            {
                return userGuidFromStr;
            }

            // Fall back to claims
            var userIdClaim = User.FindFirst("sub")?.Value ??
                              User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userGuid))
            {
                throw new UnauthorizedAccessException("User not authenticated or invalid user ID");
            }

            return userGuid;
        }

        /// <summary>
        /// Gets the current user entity from the request context.
        /// Throws UnauthorizedException if the user cannot be found.
        /// </summary>
        protected User GetCurrentUser()
        {
            if (HttpContext.Items.TryGetValue("CurrentUser", out var userObj) &&
                userObj is User user)
            {
                return user;
            }

            throw new UnauthorizedAccessException("User not authenticated or invalid user ID");
        }

        /// <summary>
        /// Tries to get the current user's ID without throwing an exception.
        /// </summary>
        protected bool TryGetUserId(out Guid userId)
        {
            try
            {
                userId = GetUserId();
                return true;
            }
            catch
            {
                userId = Guid.Empty;
                return false;
            }
        }

        /// <summary>
        /// Gets the current user's email from claims.
        /// </summary>
        protected string GetUserEmail()
        {
            // Try from HttpContext.Items first
            if (HttpContext.Items.TryGetValue("Email", out var emailObj) &&
                emailObj is string email &&
                !string.IsNullOrEmpty(email))
            {
                return email;
            }

            // Fall back to claims
            var emailClaim = User.FindFirst(ClaimTypes.Email)?.Value ??
                            User.FindFirst("email")?.Value;

            if (string.IsNullOrEmpty(emailClaim))
            {
                throw new UnauthorizedAccessException("User not authenticated or invalid user ID");
            }

            return emailClaim;
        }
    }
}