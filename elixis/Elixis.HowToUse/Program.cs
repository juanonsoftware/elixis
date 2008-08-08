using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Elixis.EncryptionOptions;

namespace Elixis.HowToUse
{
    class Program
    {
        private static AESEncryptor fAESEncryptor = new AESEncryptor();
        private static TripleDESEncryptor fTripleDESEncryptor = new TripleDESEncryptor();

        static void Main(string[] args)
        {
            string originalText = "Hello! This is Elixis...";
            string password = "My Password";

            Console.WriteLine("AES Encryption \n ");
            
            // Encrypt with AES.
            string AES128 = fAESEncryptor.Encrypt(originalText, password, AESBits.BITS128);
            Console.WriteLine("AES 128: " + AES128);
                        
            byte [] AES192 = fAESEncryptor.Encrypt(Encoding.ASCII.GetBytes(originalText), password, AESBits.BITS192);
            Console.WriteLine("AES 192: " + Encoding.Default.GetString(AES192));
            
            string AES256 = fAESEncryptor.Encrypt(originalText, password, AESBits.BITS256);
            Console.WriteLine("AES 256: " + AES256);
            
            // Decrypt with AES.
            string decryptedAES128 = fAESEncryptor.Decrypt(AES128, password, AESBits.BITS128);
            Console.WriteLine("Decrypted AES 128: " + decryptedAES128);
            
            byte[] decryptedAES192 = fAESEncryptor.Decrypt(AES192, password, AESBits.BITS192);
            Console.WriteLine("Decrypted AES 192: " + Encoding.ASCII.GetString(decryptedAES192));
            
            string decryptedAES256 = fAESEncryptor.Decrypt(AES256, password, AESBits.BITS256);
            Console.WriteLine("Decrypted AES 256: " + decryptedAES256);
            
            
            Console.WriteLine("\n\nTripleDES Encryption \n ");

            // Encrypt with TripleDES.
            byte[] tripleDES = fTripleDESEncryptor.Encrypt(Encoding.ASCII.GetBytes(originalText), password);
            Console.WriteLine("TripleDES: " + Encoding.Default.GetString(tripleDES));
            
            // Decrypt with TripleDES.
            byte[] decryptedtripleDES = fTripleDESEncryptor.Decrypt(tripleDES, password);
            Console.WriteLine("Decrypted TripleDES: " + Encoding.Default.GetString(decryptedtripleDES));

                               

            Console.Read();
        }
    }
}
