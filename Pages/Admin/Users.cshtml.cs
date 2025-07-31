using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Demo.Data;
using Demo.Models;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace Demo.Pages.Admin
{
    [Authorize]
    public class UsersModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<UsersModel> _logger;

        public UsersModel(ApplicationDbContext context, ILogger<UsersModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        public List<User> Users { get; set; } = new();
        public string? Message { get; set; }
        public string? Error { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            try
            {
                // Requirement 3: Data sorted by last login time
                Users = await _context.Users
                    .OrderByDescending(u => u.LastLogin)
                    .ToListAsync();

                return Page();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading users");
                Error = "Error loading user data. Please try again.";
                return Page();
            }
        }

        public async Task<IActionResult> OnPostBlockUsersAsync([FromForm] int[] userIds)
        {
            if (userIds == null || userIds.Length == 0)
            {
                Error = "No users selected for blocking.";
                return RedirectToPage();
            }

            try
            {
                var currentUserId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
                var users = await _context.Users
                    .Where(u => userIds.Contains(u.Id))
                    .ToListAsync();

                if (!users.Any())
                {
                    Error = "Selected users not found.";
                    return RedirectToPage();
                }

                var blockedCount = 0;
                var selfBlocked = false;

                foreach (var user in users)
                {
                    if (user.Status != UserStatus.Blocked)
                    {
                        user.Status = UserStatus.Blocked;
                        blockedCount++;

                        if (user.Id == currentUserId)
                        {
                            selfBlocked = true;
                        }
                    }
                }

                if (blockedCount > 0)
                {
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Blocked {Count} users", blockedCount);
                }

                if (selfBlocked)
                {
                    await HttpContext.SignOutAsync();
                    return RedirectToPage("/Account/Login", new { message = "You have blocked yourself and have been logged out." });
                }

                Message = blockedCount > 0 ? $"Successfully blocked {blockedCount} user(s)." : "No users were blocked.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error blocking users");
                Error = "An error occurred while blocking users. Please try again.";
            }

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostUnblockUsersAsync([FromForm] int[] userIds)
        {
            if (userIds == null || userIds.Length == 0)
            {
                Error = "No users selected for unblocking.";
                return RedirectToPage();
            }

            try
            {
                var users = await _context.Users
                    .Where(u => userIds.Contains(u.Id))
                    .ToListAsync();

                if (!users.Any())
                {
                    Error = "Selected users not found.";
                    return RedirectToPage();
                }

                var unblockedCount = 0;

                foreach (var user in users)
                {
                    if (user.Status == UserStatus.Blocked)
                    {
                        user.Status = UserStatus.Active;
                        unblockedCount++;
                    }
                }

                if (unblockedCount > 0)
                {
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Unblocked {Count} users", unblockedCount);
                    Message = $"Successfully unblocked {unblockedCount} user(s).";
                }
                else
                {
                    Message = "No users were unblocked.";
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error unblocking users");
                Error = "An error occurred while unblocking users. Please try again.";
            }

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostDeleteUsersAsync([FromForm] int[] userIds)
        {
            if (userIds == null || userIds.Length == 0)
            {
                Error = "No users selected for deletion.";
                return RedirectToPage();
            }

            try
            {
                var currentUserId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
                var users = await _context.Users
                    .Where(u => userIds.Contains(u.Id))
                    .ToListAsync();

                if (!users.Any())
                {
                    Error = "Selected users not found.";
                    return RedirectToPage();
                }

                var deletedCount = 0;
                var selfDeleted = false;

                foreach (var user in users)
                {
                    if (user.Status != UserStatus.Deleted)
                    {
                        user.Status = UserStatus.Deleted;
                        deletedCount++;

                        if (user.Id == currentUserId)
                        {
                            selfDeleted = true;
                        }
                    }
                }

                if (deletedCount > 0)
                {
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Deleted {Count} users", deletedCount);
                }

                if (selfDeleted)
                {
                    await HttpContext.SignOutAsync();
                    return RedirectToPage("/Account/Login", new { message = "You have deleted yourself and have been logged out." });
                }

                Message = deletedCount > 0 ? $"Successfully deleted {deletedCount} user(s)." : "No users were deleted.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting users");
                Error = "An error occurred while deleting users. Please try again.";
            }

            return RedirectToPage();
        }
    }
}