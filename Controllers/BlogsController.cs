using System.Threading.Tasks;
using blog_api.Database;
using blog_api.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using blog_api.Models.Blogs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace blog_api.Controllers
{   

    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class BlogsController: ControllerBase
    {   
        private readonly DataContext _context;

        public BlogsController(DataContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<IActionResult> GetBlogs()
        {
            var items = await _context.Blogs.ToListAsync();
            return Ok(items);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetBlog(int id)
        {
            var item = await _context.Blogs.FirstOrDefaultAsync(x => x.Id == id);

            if (item == null)
            {
                return NotFound();
            }
            return Ok(item);
        }


        [HttpPost]
        public async Task<IActionResult> CreateBlog(Blog data)
        {   
            if (ModelState.IsValid)
            {
                await _context.Blogs.AddAsync(data);
                await _context.SaveChangesAsync();

                return CreatedAtAction("GetBlog", new { data.Id }, data);
            }

            return new JsonResult("Failure") {StatusCode = 500};
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateBlog(Blog data, int id)
        {   
            if (id != data.Id)
            {
                return BadRequest();
            }

            var item = await _context.Blogs.FirstOrDefaultAsync(x => x.Id == id);
            if (item == null)
            {
                return NotFound();
            }

            //can be done with automapper
            item.Title = data.Title;
            item.Content = data.Content; 
            
            await _context.SaveChangesAsync();

            return NoContent();
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteBlog(int id)
        {
            var item = await _context.Blogs.FirstOrDefaultAsync(x => x.Id == id);
            if (item == null)
            {
                return NotFound();
            }
            _context.Blogs.Remove(item);
            await _context.SaveChangesAsync();

            return Ok(item);
        }
    }
}