using AngularAuthenApi.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace AngularAuthenApi.Context
{
    public class AppDbContext :DbContext
    {

        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

         public DbSet<User> Users  { get; set; }

        public void IncrementIds()
        {
            var maxId = Users.Max(e => e.Id);
  
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().ToTable("users");
        }
    }




}
