using AngularAuthenApi.Models;
using MailKit.Net.Smtp;
using MimeKit;
using System.Linq.Expressions;
using static Org.BouncyCastle.Math.EC.ECCurve;

namespace AngularAuthenApi.UtilityService
{
    public class EmailService : IEmailService
    {

        private IConfiguration _config;

        public EmailService(IConfiguration configuration)
        {
            _config = configuration;
        }



        // Create Email Message 
        public void SendEmail(EmailModel emailModel)
        {
            var emailMessage = new MimeMessage(); // Package must be downloaded name => MailKit
            var from = _config["EmailSetting:From"]; // Admin - The Programmer 
            emailMessage.From.Add(new MailboxAddress("AH-AUTHENTICATION!", from));
            emailMessage.To.Add(new MailboxAddress(emailModel.To, emailModel.To)); // Who Want To Send - User.
            emailMessage.Subject = emailModel.subjectEmail;
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Html)
            {
                Text = String.Format(emailModel.contentEmail)
            };

            // Send Message to The User 
            using (var client = new SmtpClient())
            {
                try
                {
                    var host = _config["EmailSetting:SmtpServer"];
                    if (host == null)
                    {
                        throw new ArgumentNullException(nameof(host));
                    }

                    client.Connect(host, 465, true);
                    client.Authenticate(_config["EmailSetting:From"], _config["EmailSetting:Password"]);
                    client.Send(emailMessage);
                }
                catch (Exception ex)
                {
                    throw;
                }
                finally
                {
                    client.Disconnect(true);
                    client.Dispose();
                }
            }
        }




























    }
}

