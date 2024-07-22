using System.ComponentModel.DataAnnotations;

namespace APIRoleBasedTokenAuthCore.ViewModels
{
    public class RegisterViewModel
    {
        [Key]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
        public string FirstName { get; set; }

        // Add Your Custom Property....
        public string LastName { get; set; }

        // Add Your Custom Property....
        public int Age { get; set; }

        // Add Your Custom Property....
        public string MobileNo { get; set; }

        // Add Your Custom Property....
        public double Salary { get; set; }
    }
}
