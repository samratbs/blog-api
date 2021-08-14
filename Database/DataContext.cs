using blog_api.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace blog_api.Database
{
    public class DataContext: IdentityDbContext
    {
        public virtual DbSet<Blog> Blogs {get; set;}

        public DataContext(DbContextOptions<DataContext> options): base(options)
        {

        }
    }
}