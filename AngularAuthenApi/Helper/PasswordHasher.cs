﻿using System.Security.Cryptography;
namespace AngularAuthenApi.Helper
{
    public class PasswordHasher
    {
        private static RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        private static readonly int SaltSize = 16;
        private static readonly int HashSize = 20;
        private static readonly int Itreations = 1000;



        // This function hashing the password 
        public static string HashPassword(string password)
        {
            byte[] salt;
            rng.GetBytes(salt = new byte[SaltSize]);
            var key= new Rfc2898DeriveBytes(password,salt,Itreations);
            var hash = key.GetBytes(HashSize);

            var hashBytes = new byte[SaltSize + HashSize]; //16+20=36
            Array.Copy(salt,0, hashBytes,0,SaltSize);
            Array.Copy(hash, 0, hashBytes, SaltSize, HashSize);

            var base64Hash = Convert.ToBase64String(hashBytes);

            return base64Hash;
        }


        //  Use this function to VerifyPassword from database after Hashing.
        public static bool VerifyPassword(string inputPassword , string base64PasswordHashed)
        {
            var hashBytes = Convert.FromBase64String(base64PasswordHashed);
            var salt = new byte[SaltSize];  
            Array.Copy(hashBytes,0, salt,0,SaltSize);
            var key = new Rfc2898DeriveBytes(inputPassword, salt, Itreations);
            byte[]  hash = key.GetBytes(HashSize);

            for (var i = 0; i < HashSize; i++)
            {
                if (hashBytes[i+SaltSize] != hash[i])
                 return false;
               
            }
            return true;


        }

    }
}
