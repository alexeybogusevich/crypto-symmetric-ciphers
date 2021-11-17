using KNU.Crypto.SymmetricCiphers.AES.Parameters;
using KNU.Crypto.SymmetricCiphers.AES.Implementation;
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
            var cipherKey = RandomManager.NextBytes(cipherKeyLength);

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
