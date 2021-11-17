using KNU.Crypto.SymmetricCiphers.Common.Interfaces;
using KNU.Crypto.SymmetricCiphers.Kalyna.Parameters;
using System;

namespace KNU.Crypto.SymmetricCiphers.Kalyna.Implementation
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
        private readonly int Rounds;

        /// <summary>
        /// Cipher Key.
        /// </summary>
        private readonly byte[] key;

        /// <summary>
        /// Values derived from the Cipher Key using the Key Expansion routine. Key schedule.
        /// </summary>
        private byte[,] w;

        public Algorithm(byte[] key)
        {
            var bitLength = key.Length * 8;

            switch ((KeySize)bitLength)
            {
                case KeySize.Bits128:
                    Rounds = 10;
                    break;
                case KeySize.Bits256:
                    Rounds = 14;
                    break;
                case KeySize.Bits512:
                    Rounds = 18;
                    break;
                default:
                    throw new ArgumentException($"KeySize not supported: {key.Length}");
            }
        }

        public byte[] Encode(byte[] plainBytes)
        {
            throw new NotImplementedException();
        }

        public byte[] Decode(byte[] cipherBytes)
        {
            throw new NotImplementedException();
        }

        private bool CheckLength(BlockSize blockSize)
        {
            var keySize = (KeySize)key.Length;

            return blockSize switch
            {
                BlockSize.Bits128 => keySize == KeySize.Bits128 || keySize == KeySize.Bits256,
                BlockSize.Bits256 => keySize == KeySize.Bits256 || keySize == KeySize.Bits512,
                BlockSize.Bits512 => keySize == KeySize.Bits512,
                _ => throw new ArgumentException($"BlockSize not supported: {blockSize}"),
            };
        }
    }
}
