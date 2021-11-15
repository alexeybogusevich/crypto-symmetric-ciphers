using KNU.Crypto.SymmetricCiphers.Common.Interfaces;
using System;

namespace KNU.Crypto.SymmetricCiphers.AES.Implementation
{
    public class Algorithm : IAlgorithm
    {
        /// <summary>
        /// Number of columns (32-bit words) comprising the State. For this standard, Nb = 4. 
        /// </summary>
        private readonly int Nb = 4;

        /// <summary>
        /// Number of 32-bit words comprising the Cipher Key. For this standard, Nk = 4, 6, or 8.
        /// </summary>
        private readonly int Nk;

        /// <summary>
        /// Number of rounds, which is a function of Nk and Nb (which is fixed). For this standard, Nr = 10, 12, or 14.
        /// </summary>
        private readonly int Nr;

        /// <summary>
        /// Cipher Key.
        /// </summary>
        private readonly byte[] key;

        public Algorithm(byte[] key, KeySize keySize = KeySize.Bits128)
        {
            if (key.Length != ((int)keySize))
            {
                throw new ArgumentException();
            }

            this.key = new byte[Nk * 4];
            key.CopyTo(this.key, 0);

            switch (keySize)
            {
                case KeySize.Bits128:
                    Nk = 4;
                    Nr = 10;
                    break;
                case KeySize.Bits192:
                    Nk = 6;
                    Nr = 12;
                    break;
                case KeySize.Bits256:
                    Nk = 8;
                    Nr = 14;
                    break;
                default:
                    throw new ArgumentException($"KeySize not supported: {keySize}");
            }
        }

        public byte[] Encode(byte[] plainText)
        {
            var state = new State(plainText, 4, Nb);



            throw new NotImplementedException();
        }

        public byte[] Decode(byte[] cipherText)
        {
            throw new NotImplementedException();
        }
    }
}
