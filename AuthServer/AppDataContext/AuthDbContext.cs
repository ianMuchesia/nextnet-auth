using AuthServer.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthServer.AppDataContext;



    // TodoDbContext class inherits from DbContext
     public class AuthDbContext : DbContext
     {

        // DbSettings field to store the connection string
         private readonly DbSettings _dbsettings;

            // Constructor to inject the DbSettings model
         public AuthDbContext(IOptions<DbSettings> dbSettings)
         {
             _dbsettings = dbSettings.Value;
         }


        // DbSet property to represent the Todo table
         public DbSet<User> Users { get; set; }

         // Configuring the database provider and connection string

         protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
         {
             optionsBuilder.UseSqlServer(_dbsettings.ConnectionString);
         }

            // Configuring the model for the Todo entity
         protected override void OnModelCreating(ModelBuilder modelBuilder)
         {
             modelBuilder.Entity<User>()
                 .ToTable("TodoAPI")
                 .HasKey(x => x.Id);
         }
     }
