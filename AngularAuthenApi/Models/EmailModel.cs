namespace AngularAuthenApi.Models
{
    
    public class EmailModel
    {
        public EmailModel(string to, string subjectEmail, string contentEmail)
        {
            To = to;
            this.subjectEmail = subjectEmail;
            this.contentEmail = contentEmail;   
        }

        public string To { get; set; }
        public string subjectEmail { get; set; }
        public string contentEmail { get; set; }

    }
}

