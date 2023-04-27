namespace AngularAuthenApi.Models.Dto
{   /*Note: Record representing data that is typically read-only
    And needs to be shared across different parts of an application*/

    public record ResetPasswordDto
    {
        public string Email { get; set; }
        public string EmailToken { get; set; }
        public string NewPassword { get; set; }
        public string ConfirmPassword { get; set; }
    }
}
