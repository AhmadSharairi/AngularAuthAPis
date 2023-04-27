using AngularAuthenApi.Context;
using AngularAuthenApi.UtilityService;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

//This config make Applied in diffrent Domain from Api_url and Angular_url when call in the Backend
builder.Services.AddCors(option =>
{
    option.AddPolicy("MyPolicy", builder =>
                   builder.AllowAnyOrigin().
                    AllowAnyMethod().
                    AllowAnyHeader());

});


builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

/**********My Own Code Added**********/

//Config Dbcontext to connect to the DataBase (SqlServer)
builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

// Config  EmailServices to use in controller as a Dependency Injection
builder.Services.AddScoped<IEmailService, EmailService>();



/********************************/

// Config JWT after added to Usercontroller 
builder.Services.AddAuthentication(x =>
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme    = JwtBearerDefaults.AuthenticationScheme;

}).AddJwtBearer(x =>
{
    x.RequireHttpsMetadata = false;
    x.SaveToken = true;
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("veryverysecret......")),
        ValidateAudience = false,
        ValidateIssuer = false,
        ClockSkew= TimeSpan.Zero, // make specific time and detemine becaue the time in here at least 5min
     };
});




var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();     // middleware component
    app.UseSwaggerUI();
    

}

app.UseHttpsRedirection();


/****My Own Add*****/
app.UseCors("MyPolicy"); // First , UseCors Must Be Above of the Authentications methods Call 
app.UseAuthentication(); // Second ,UseAuthentication must be above of Authorizations Method
app.UseAuthorization(); //  Third , last  Use Authorization
/******************/
app.MapControllers();
app.Run();
