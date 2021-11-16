using KNU.Crypto.SymmetricCiphers.AES.Data;
using KNU.Crypto.SymmetricCiphers.AES.Implementation;
using KNU.Crypto.SymmetricCiphers.Common.Services;
using System;
using System.Text;

namespace KNU.Crypto.SymmetricCiphers
{
    class Program
    {
        const int AESTextBitsLength = 128;
        const int AESKeyBitsLength = 128;

        static void Main(string[] args)
        {
            //var plainTextLength = AESTextBitsLength / (sizeof(char) * 8);
            //var plainText = RandomManager.NextString(plainTextLength);
            //var plainBytes = Encoding.Unicode.GetBytes(plainText);

            var plainBytes = Examples.AppendixB_PlainText;
            var plainText = Encoding.ASCII.GetString(plainBytes);

            Console.WriteLine($"PLAIN: {plainText}");

            //var cipherKeyLength = AESKeyBitsLength / (sizeof(byte) * 8);
            //var cipherKey = RandomManager.NextBytes(cipherKeyLength);

            var cipherKey = Examples.AppendixB_CipherKey;

            var algorithm = new Algorithm(cipherKey);

            var encodedBytes = algorithm.Encode(plainBytes);
            var encodedText = Encoding.Unicode.GetString(encodedBytes);

            Console.WriteLine($"ENCODED: {encodedText}");

            var decodedBytes = algorithm.Decode(encodedBytes);
            var decodedText = Encoding.Unicode.GetString(decodedBytes);

            Console.WriteLine($"DECODED: {decodedText}");

            Console.ReadKey();
        }
    }
}
