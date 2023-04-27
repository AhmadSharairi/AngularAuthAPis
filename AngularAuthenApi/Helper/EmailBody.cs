namespace AngularAuthenApi.Helper
{
    public static class EmailBody
    {
        public static string EmailStringBody(string email , string emailToken )
        {

            return $@"
         
				<html>
				<head>
					<title>Password Reset Request</title>
				</head>
				<body>
					<div style=""background-color:#f2f2f2; padding:50px;"">
						<div style=""background-color:#fff; border-radius:5px; padding:30px;"">
							<h1>Password Reset Request</h1>
							<p>We have received a request to reset the password for your account. To proceed, click on the link below:</p>
							<p><a href=""http://localhost:4200/reset?email={email}&code={emailToken}"" style=""background-color:#4CAF50; color:#fff; padding:10px 20px; border-radius:5px; text-decoration:none;"">Reset Password</a></p>
							<p>If you did not make this request, please ignore this message and your password will remain unchanged.</p>
							<p>Thank you,</p>
							<p> Ahmad Al-Sharairi Team </p>
						</div>
					</div>
				</body>
				</html>
				 ";
        }

    }
}
