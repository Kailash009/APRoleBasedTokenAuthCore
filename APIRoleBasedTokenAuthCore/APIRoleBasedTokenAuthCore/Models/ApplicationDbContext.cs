using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace APIRoleBasedTokenAuthCore.Models
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>   // Add this Application User Model Here.....
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {

        }
    }
}
