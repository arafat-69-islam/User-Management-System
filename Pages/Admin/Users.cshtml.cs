using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
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

        public UsersModel(ApplicationDbContext context)
        {
            _context = context;
        }

        public List<User> Users { get; set; } = new();
        public string? Message { get; set; }
        public string? Error { get; set; }

        public async Task OnGetAsync()
        {
            Users = await _context.Users
                .OrderByDescending(u => u.LastLogin)
                .ToListAsync();
        }

        public async Task<IActionResult> OnPostBlockUsersAsync([FromForm] int[] userIds)
        {
            try
            {
                var currentUserId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
                var users = await _context.Users
                    .Where(u => userIds.Contains(u.Id))
                    .ToListAsync();

                foreach (var user in users)
                {
                    user.Status = UserStatus.Blocked;
                    if (user.Id == currentUserId)
                    {
                        await HttpContext.SignOutAsync();
                        return RedirectToPage("/Account/Login", new { message = "You blocked yourself and have been logged out" });
                    }
                }

                await _context.SaveChangesAsync();
                Message = "Users blocked successfully";
            }
            catch (Exception ex)
            {
                Error = $"Error blocking users: {ex.Message}";
            }

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostUnblockUsersAsync([FromForm] int[] userIds)
        {
            try
            {
                var users = await _context.Users
                    .Where(u => userIds.Contains(u.Id))
                    .ToListAsync();

                foreach (var user in users)
                {
                    user.Status = UserStatus.Active;
                }

                await _context.SaveChangesAsync();
                Message = "Users unblocked successfully";
            }
            catch (Exception ex)
            {
                Error = $"Error unblocking users: {ex.Message}";
            }

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostDeleteUsersAsync([FromForm] int[] userIds)
        {
            try
            {
                var currentUserId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
                var users = await _context.Users
                    .Where(u => userIds.Contains(u.Id))
                    .ToListAsync();

                _context.Users.RemoveRange(users);
                await _context.SaveChangesAsync();

                if (userIds.Contains(currentUserId))
                {
                    await HttpContext.SignOutAsync();
                    return RedirectToPage("/Account/Login", new { message = "You deleted yourself and have been logged out" });
                }

                Message = "Users deleted successfully";
            }
            catch (Exception ex)
            {
                Error = $"Error deleting users: {ex.Message}";
            }

            return RedirectToPage();
        }
    }
}