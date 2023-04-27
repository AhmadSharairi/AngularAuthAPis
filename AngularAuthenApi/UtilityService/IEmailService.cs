using AngularAuthenApi.Models;

namespace AngularAuthenApi.UtilityService
{
    public interface IEmailService
    {
        void SendEmail(EmailModel emailModel);
    }
}
