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
using Elixis.EncryptionOptions;

namespace Elixis
{
    public class AESEncryptor
    {
        public AESEncryptor()
        {
        }

        private byte[] iEncrypt(byte[] data, byte[] key, byte[] iV)
        {
            MemoryStream ms = new MemoryStream();

            Rijndael alg = Rijndael.Create();
            alg.Key = key;

            alg.IV = iV;
            CryptoStream cs = new CryptoStream(ms, alg.CreateEncryptor(), CryptoStreamMode.Write);

            cs.Write(data, 0, data.Length);
            cs.Close();
            byte[] encryptedData = ms.ToArray();
            return encryptedData;
        }

        /// <summary>
        /// Encrypt string with AES algorith.
        /// </summary>
        /// <param name="data">String to encrypt.</param>
        /// <param name="password">Password to use for encryption.</param>
        /// <param name="bits">Encryption bits.</param>
        /// <returns>Encrypted string.</returns>
        public string Encrypt(string data, string password, AESBits bits)
        {
            byte[] clearBytes = System.Text.Encoding.Unicode.GetBytes(data);

            PasswordDeriveBytes pdb = new PasswordDeriveBytes(password, new byte[] { 0x00, 0x01, 0x02, 0x1C, 0x1D, 0x1E, 0x03, 0x04, 0x05, 0x0F, 0x20, 0x21, 0xAD, 0xAF, 0xA4 });

            switch (bits)
            {
                case AESBits.BITS128:
                    return Convert.ToBase64String(iEncrypt(clearBytes, pdb.GetBytes(16), pdb.GetBytes(16)));
                    break;

                case AESBits.BITS192:
                    return Convert.ToBase64String(iEncrypt(clearBytes, pdb.GetBytes(24), pdb.GetBytes(16)));
                    break;

                case AESBits.BITS256:
                    return Convert.ToBase64String(iEncrypt(clearBytes, pdb.GetBytes(32), pdb.GetBytes(16)));
                    break;
            }
            return null;
        }

        /// <summary>
        /// Encrypt byte array with AES algorithm.
        /// </summary>
        /// <param name="data">Bytes to encrypt.</param>
        /// <param name="password">Password to use for encryption.</param>
        /// <param name="bits">Encryption bits.</param>
        /// <returns>Encrypted bytes.</returns>
        public byte[] Encrypt(byte[] data, string password, AESBits bits)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(password, new byte[] { 0x00, 0x01, 0x02, 0x1C, 0x1D, 0x1E, 0x03, 0x04, 0x05, 0x0F, 0x20, 0x21, 0xAD, 0xAF, 0xA4 });
            switch (bits)
            {
                case AESBits.BITS128:
                    return iEncrypt(data, pdb.GetBytes(16), pdb.GetBytes(16));
                    break;

                case AESBits.BITS192:
                    return iEncrypt(data, pdb.GetBytes(24), pdb.GetBytes(16));
                    break;

                case AESBits.BITS256:
                    return iEncrypt(data, pdb.GetBytes(32), pdb.GetBytes(16));
                    break;
            }
            return null;
        }

        private byte[] iDecrypt(byte[] data, byte[] key, byte[] iv)
        {
            MemoryStream ms = new MemoryStream();
            Rijndael alg = Rijndael.Create();
            alg.Key = key;
            alg.IV = iv;
            CryptoStream cs = new CryptoStream(ms, alg.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(data, 0, data.Length);
            cs.Close();
            byte[] decryptedData = ms.ToArray();
            return decryptedData;
        }


        /// <summary>
        /// Decrypt string with AES algorithm.
        /// </summary>
        /// <param name="data">Encrypted string.</param>
        /// <param name="password">Password has been used for encryption.</param>
        /// <param name="bits">Encryption bits.</param>
        /// <returns>Decrypted string.</returns>
        public string Decrypt(string data, string password, AESBits bits)
        {
            byte[] dataToDecrypt = Convert.FromBase64String(data);

            PasswordDeriveBytes pdb = new PasswordDeriveBytes(password, new byte[] { 0x00, 0x01, 0x02, 0x1C, 0x1D, 0x1E, 0x03, 0x04, 0x05, 0x0F, 0x20, 0x21, 0xAD, 0xAF, 0xA4 });

            switch (bits)
            {
                case AESBits.BITS128:
                    return System.Text.Encoding.Unicode.GetString(iDecrypt(dataToDecrypt, pdb.GetBytes(16), pdb.GetBytes(16)));
                    break;

                case AESBits.BITS192:
                    return System.Text.Encoding.Unicode.GetString(iDecrypt(dataToDecrypt, pdb.GetBytes(24), pdb.GetBytes(16)));
                    break;

                case AESBits.BITS256:
                    return System.Text.Encoding.Unicode.GetString(iDecrypt(dataToDecrypt, pdb.GetBytes(32), pdb.GetBytes(16)));
                    break;
            }
            return null;
        }

        /// <summary>
        /// Decrypt byte array with AES algorithm.
        /// </summary>
        /// <param name="data">Encrypted byte array.</param>
        /// <param name="password">Password has been used for encryption.</param>
        /// <param name="bits">Encryption bits.</param>
        /// <returns>Decrypted byte array.</returns>
        public byte[] Decrypt(byte[] data, string password, AESBits bits)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(password, new byte[] { 0x00, 0x01, 0x02, 0x1C, 0x1D, 0x1E, 0x03, 0x04, 0x05, 0x0F, 0x20, 0x21, 0xAD, 0xAF, 0xA4 });

            switch (bits)
            {
                case AESBits.BITS128:
                    return iDecrypt(data, pdb.GetBytes(16), pdb.GetBytes(16));
                    break;

                case AESBits.BITS192:
                    return iDecrypt(data, pdb.GetBytes(24), pdb.GetBytes(16));
                    break;

                case AESBits.BITS256:
                    return iDecrypt(data, pdb.GetBytes(32), pdb.GetBytes(16));
                    break;
            }
            return null;
        }

    }

}
