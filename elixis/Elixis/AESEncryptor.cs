/*The MIT License

Copyright (c) 2008-2009 codeforte.org

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

/**
 *
 * @author Nikos Siatras
 */
namespace Elixis
{
    public class AESEncryptor
    {
        private string fPassword;
        private AESBits fEncryptionBits;
        private byte[] fSalt = new byte[] { 0x00, 0x01, 0x02, 0x1C, 0x1D, 0x1E, 0x03, 0x04, 0x05, 0x0F, 0x20, 0x21, 0xAD, 0xAF, 0xA4 };

        /// <summary>
        /// Initialize new AESEncryptor.
        /// </summary>
        /// <param name="password">The password to use for encryption/decryption.</param>
        /// <param name="encryptionBits">Encryption bits (128,192,256).</param>
        public AESEncryptor(string password, AESBits encryptionBits)
        {
            fPassword = password;
            fEncryptionBits = encryptionBits;
        }
        
        /// <summary>
        /// Initialize new AESEncryptor.
        /// </summary>
        /// <param name="password">The password to use for encryption/decryption.</param>
        /// <param name="encryptionBits">Encryption bits (128,192,256).</param>
        /// <param name="salt">Salt bytes. Bytes length must be 15.</param>
        public AESEncryptor(string password, AESBits encryptionBits, byte[] salt)
        {
            fPassword = password;
            fEncryptionBits = encryptionBits;
            fSalt = salt;
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
        public string Encrypt(string data)
        {
            byte[] clearBytes = System.Text.Encoding.Unicode.GetBytes(data);

            PasswordDeriveBytes pdb = new PasswordDeriveBytes(fPassword, fSalt);

            switch (fEncryptionBits)
            {
                case AESBits.BITS128:
                    return Convert.ToBase64String(iEncrypt(clearBytes, pdb.GetBytes(16), pdb.GetBytes(16)));

                case AESBits.BITS192:
                    return Convert.ToBase64String(iEncrypt(clearBytes, pdb.GetBytes(24), pdb.GetBytes(16)));

                case AESBits.BITS256:
                    return Convert.ToBase64String(iEncrypt(clearBytes, pdb.GetBytes(32), pdb.GetBytes(16)));
            }
            return null;
        }

        /// <summary>
        /// Encrypt byte array with AES algorithm.
        /// </summary>
        /// <param name="data">Bytes to encrypt.</param>
        public byte[] Encrypt(byte[] data)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(fPassword,  fSalt);
            switch (fEncryptionBits)
            {
                case AESBits.BITS128:
                    return iEncrypt(data, pdb.GetBytes(16), pdb.GetBytes(16));

                case AESBits.BITS192:
                    return iEncrypt(data, pdb.GetBytes(24), pdb.GetBytes(16));

                case AESBits.BITS256:
                    return iEncrypt(data, pdb.GetBytes(32), pdb.GetBytes(16));
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
        public string Decrypt(string data)
        {
            byte[] dataToDecrypt = Convert.FromBase64String(data);

            PasswordDeriveBytes pdb = new PasswordDeriveBytes(fPassword,  fSalt);

            switch (fEncryptionBits)
            {
                case AESBits.BITS128:
                    return System.Text.Encoding.Unicode.GetString(iDecrypt(dataToDecrypt, pdb.GetBytes(16), pdb.GetBytes(16)));

                case AESBits.BITS192:
                    return System.Text.Encoding.Unicode.GetString(iDecrypt(dataToDecrypt, pdb.GetBytes(24), pdb.GetBytes(16)));

                case AESBits.BITS256:
                    return System.Text.Encoding.Unicode.GetString(iDecrypt(dataToDecrypt, pdb.GetBytes(32), pdb.GetBytes(16)));
            }
            return null;
        }

        /// <summary>
        /// Decrypt byte array with AES algorithm.
        /// </summary>
        /// <param name="data">Encrypted byte array.</param>
        public byte[] Decrypt(byte[] data)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(fPassword, fSalt);

            switch (fEncryptionBits)
            {
                case AESBits.BITS128:
                    return iDecrypt(data, pdb.GetBytes(16), pdb.GetBytes(16));

                case AESBits.BITS192:
                    return iDecrypt(data, pdb.GetBytes(24), pdb.GetBytes(16));

                case AESBits.BITS256:
                    return iDecrypt(data, pdb.GetBytes(32), pdb.GetBytes(16));
            }
            return null;
        }

        /// <summary>
        /// Encryption/Decryption password.
        /// </summary>
        public string Password
        {
            get { return fPassword; }
            set { fPassword = value; }
        }

        /// <summary>
        /// Encryption/Decryption bits.
        /// </summary>
        public AESBits EncryptionBits
        {
            get { return fEncryptionBits; }
            set { fEncryptionBits = value; }
        }

        /// <summary>
        /// Salt bytes (bytes length must be 15).
        /// </summary>
        public byte[] Salt
        {
            get { return fSalt; }
            set { fSalt = value; }
        }
    }

}
