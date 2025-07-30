using System.ComponentModel.DataAnnotations;

namespace Demo.Models
{
    public enum UserStatus { Active, Blocked, Deleted }

    public class User
    {
        public int Id { get; set; }

        [Required, StringLength(100)]
        public string Name { get; set; } = string.Empty;

        [Required]
        public DateTime DateOfBirth { get; set; }

        [Required, StringLength(20)]
        public string MobileNumber { get; set; } = string.Empty;

        [Required, EmailAddress, StringLength(100)]
        public string Email { get; set; } = string.Empty;

        [Required, StringLength(10)]
        public string Gender { get; set; } = string.Empty;

        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        public DateTime LastLogin { get; set; }

        public UserStatus Status { get; set; } = UserStatus.Active;
    }
}