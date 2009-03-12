/*The MIT License

Copyright (c) 2008 Nikos K. Siatras

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Elixis.EncryptionOptions;

namespace Elixis.HowToUse
{
    class Program
    {
        private static AESEncryptor fAESEncryptor = new AESEncryptor("My Password", AESBits.BITS256);
        private static TripleDESEncryptor fTripleDESEncryptor = new TripleDESEncryptor("My Password");
        private static MD5Encryptor fMD5Encryptor = new MD5Encryptor();

        static void Main(string[] args)
        {          
            string originalText = "Hello! This is Elixis...";
            string password = "My Password";

            Console.WriteLine("AES Encryption \n ");
            
            // Encrypt with AES.
            string encryptedAESString = fAESEncryptor.Encrypt(originalText);
            Console.WriteLine("Encrypted AES: " + encryptedAESString);

            // Decrypt with AES.
            string decryptedAESString = fAESEncryptor.Decrypt(encryptedAESString);
            Console.WriteLine("Decrypted AES: " + decryptedAESString);
            
            Console.WriteLine("\n\nTripleDES Encryption \n ");

            // Encrypt with TripleDES.
            byte[] tripleDESEncryptedString = fTripleDESEncryptor.Encrypt(Encoding.ASCII.GetBytes(originalText));
            Console.WriteLine("Encrypted TripleDES: " + Encoding.Default.GetString(tripleDESEncryptedString));
            
            // Decrypt with TripleDES.
            byte[] tripleDESDecryptedString = fTripleDESEncryptor.Decrypt(tripleDESEncryptedString);
            Console.WriteLine("Decrypted TripleDES: " + Encoding.Default.GetString(tripleDESDecryptedString));

            Console.WriteLine("\n\nMD5 Encryption \n ");
            
            // Encrypt with MD5.
            string md5 = fMD5Encryptor.GetMD5(originalText);
            Console.WriteLine("MD5: " + md5);

            string md5_bytes = fMD5Encryptor.GetMD5(Encoding.ASCII.GetBytes(originalText));
            Console.WriteLine("MD5_bytes: " + md5_bytes);
                               
            Console.Read();
        }
    }
}
