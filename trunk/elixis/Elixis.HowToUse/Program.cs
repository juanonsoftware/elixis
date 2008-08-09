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
        private static AESEncryptor fAESEncryptor = new AESEncryptor();
        private static TripleDESEncryptor fTripleDESEncryptor = new TripleDESEncryptor();
        private static MD5Encryptor fMD5Encryptor = new MD5Encryptor();

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
