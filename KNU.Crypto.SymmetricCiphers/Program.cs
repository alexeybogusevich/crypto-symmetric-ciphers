using KNU.Crypto.SymmetricCiphers.AES.Implementation;
using KNU.Crypto.SymmetricCiphers.AES.Parameters;
using KNU.Crypto.SymmetricCiphers.Common.Services;
using System;
using System.Text;

namespace KNU.Crypto.SymmetricCiphers
{
    class Program
    {
        static void Main(string[] args)
        {
            var plainTextLength = (int)BlockSize.Bits128 / (sizeof(char) * 8);
            var plainText = RandomManager.NextString(plainTextLength);
            var plainBytes = Encoding.Unicode.GetBytes(plainText);

            Console.WriteLine($"PLAIN: {plainText}");

            var cipherKeyLength = (int)KeySize.Bits128 / (sizeof(byte) * 8);
            var cipherKey = RandomManager.NextString(cipherKeyLength);
            var cipherBytes = Encoding.Unicode.GetBytes(cipherKey);

            var algorithm = new Algorithm(cipherBytes);

            var encrypted = algorithm.Encrypt(plainBytes);
            var encryptedText = Encoding.Unicode.GetString(encrypted);

            Console.WriteLine($"ENCODED: {encryptedText}");

            var decryptedBytes = algorithm.Decrypt(encrypted);
            var decryptedText = Encoding.Unicode.GetString(decryptedBytes);

            Console.WriteLine($"DECODED: {decryptedText}");

            Console.ReadKey();
        }
    }
}
