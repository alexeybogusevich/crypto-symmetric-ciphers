using System;

namespace KNU.Crypto.SymmetricCiphers.Common.Services
{
    public static class RandomManager
    {
        static Random random = new Random();

        public static string NextString(int length)
        {
            const string allowedChars = "ABCDEFGHJKLMNOPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789!@$?_-";

            var chars = new char[length];

            for (int i = 0; i < length; ++i)
            {
                var selectedChar = random.Next(0, allowedChars.Length);
                chars[i] = allowedChars[selectedChar];
            }

            return new string(chars);
        }

        public static byte[] NextBytes(int length)
        {
            var bytes = new byte[length];

            random.NextBytes(bytes);

            return bytes;
        }
    }
}
