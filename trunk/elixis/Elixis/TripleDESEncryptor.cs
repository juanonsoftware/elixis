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
using System.IO;
using System.Security.Cryptography;

namespace Elixis
{
    public class TripleDESEncryptor
    {
        public TripleDESEncryptor()
        {
        }

        private byte[] iEncrypt(byte[] data, byte[] key, byte[] iv)
        {
            MemoryStream ms = new MemoryStream();
            TripleDES alg = TripleDES.Create();

            alg.Key = key;
            alg.IV = iv;

            CryptoStream cs = new CryptoStream(ms, alg.CreateEncryptor(), CryptoStreamMode.Write);

            cs.Write(data, 0, data.Length);
            cs.Close();
            return ms.ToArray();
        }

        /// <summary>
        /// Encrypt string with TripleDES algorith.
        /// </summary>
        /// <param name="data">String to encrypt.</param>
        /// <param name="password">Password to use for encryption.</param>
        /// <returns>Encrypted string.</returns>
        public string Encrypt(string data, string password)
        {
            byte[] dataToEncrypt = System.Text.Encoding.Unicode.GetBytes(data);
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(password, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });

            return Convert.ToBase64String(iEncrypt(dataToEncrypt, pdb.GetBytes(16), pdb.GetBytes(8)));
        }

        /// <summary>
        /// Encrypt byte array with TripleDES algorithm.
        /// </summary>
        /// <param name="data">Bytes to encrypt.</param>
        /// <param name="password">Password to use for encryption.</param>
        /// <returns>Encrypted bytes.</returns>
        public byte[] Encrypt(byte[] data, string password)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(password, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
            
            return iEncrypt(data, pdb.GetBytes(16), pdb.GetBytes(8));
        }


        private byte[] iDecrypt(byte[] data, byte[] key, byte[] iv)
        {
            MemoryStream ms = new MemoryStream();
            TripleDES alg = TripleDES.Create();

            alg.Key = key;
            alg.IV = iv;

            CryptoStream cs = new CryptoStream(ms, alg.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(data, 0, data.Length);
            cs.Close();

            return ms.ToArray();
        }

        /// <summary>
        /// Decrypt string with TripleDES algorithm.
        /// </summary>
        /// <param name="data">Encrypted string.</param>
        /// <param name="password">Password has been used for encryption.</param>
        /// <returns>Decrypted string.</returns>
        public string Decrypt(string data, string password)
        {
            byte[] cipherBytes = Convert.FromBase64String(data);
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(password,new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
            
            return System.Text.Encoding.Unicode.GetString(iDecrypt(cipherBytes, pdb.GetBytes(16), pdb.GetBytes(8)));
        }

        /// <summary>
        /// Decrypt byte array with TripleDES algorithm.
        /// </summary>
        /// <param name="data">Encrypted byte array.</param>
        /// <param name="password">Password has been used for encryption.</param>
        /// <returns>Decrypted byte array.</returns>
        public byte[] Decrypt(byte[] data, string password)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(password, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
            return iDecrypt(data, pdb.GetBytes(16), pdb.GetBytes(8));
        }


    }
}
