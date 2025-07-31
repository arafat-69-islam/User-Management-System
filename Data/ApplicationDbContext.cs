using Microsoft.EntityFrameworkCore;
using Demo.Models;

namespace Demo.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; } = null!;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>(entity =>
            {
                entity.HasIndex(u => u.Email).IsUnique();
                entity.Property(u => u.Name).IsRequired().HasMaxLength(100);
                entity.Property(u => u.Email).IsRequired().HasMaxLength(100);
                entity.Property(u => u.PasswordHash).IsRequired();
                entity.Property(u => u.Status).HasDefaultValue(UserStatus.Active);
                entity.Property(u => u.MobileNumber).IsRequired().HasMaxLength(20);
                entity.Property(u => u.Gender).IsRequired().HasMaxLength(10);
            });
        }
    }
}