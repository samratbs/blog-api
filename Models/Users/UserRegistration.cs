using System.ComponentModel.DataAnnotations;

namespace blog_api.Models.Users
{
    public class UserRegistration
    {   
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Username { get; set; }

        [Required]
        public string Password { get; set; }
    }
}