using KNU.Crypto.SymmetricCiphers.Kalyna.Parameters;
using System;

namespace KNU.Crypto.SymmetricCiphers.Kalyna.Implementation
{
    public class Algorithm
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

        /// <summary>
        /// Values derived from the Cipher Key using the Key Expansion routine. Key schedule.
        /// </summary>
        private byte[,] w;

        public Algorithm(BlockSize blockSize, KeySize keySize)
        {
            switch (blockSize)
            {
                case BlockSize.Bits128:
                    Nb = 2;
                    if (keySize == KeySize.Bits128)
                    {
                        Nk = 2;
                        Nr = 10;
                    }
                    else if (keySize == KeySize.Bits256)
                    {
                        Nk = 4;
                        Nr = 14;
                    }
                    else
                    {
                        throw new ArgumentNullException($"{nameof(KeySize)} not supported.");
                    }
                    break;
                case BlockSize.Bits256:
                    Nb = 4;
                    if (keySize == KeySize.Bits256)
                    {
                        Nk = 4;
                        Nr = 14;
                    }
                    else if (keySize == KeySize.Bits512)
                    {
                        Nk = 8;
                        Nr = 18;
                    }
                    else
                    {
                        throw new ArgumentNullException($"{nameof(KeySize)} not supported.");
                    }
                    break;
                case BlockSize.Bits512:
                    if (keySize == KeySize.Bits512)
                    {
                        Nk = 8;
                        Nr = 18;
                    }
                    break;
                default:
                    throw new ArgumentNullException($"{nameof(BlockSize)} not supported.");
            }
        }

        public ulong[] Encode(ulong[] plainText, ulong[] chipherKey)
        {
            int round = 0;

            ulong[] state = new ulong[Nb];

            ulong[][] roundKeys = StateManager.KeyExpansion(chipherKey, ref state, Nb, Nk, Nr);

            Array.Copy(plainText, state, Nb);

            StateManager.AddRoundKey(roundKeys[round], state);
            for (round = 1; round < Nr; ++round)
            {
                StateManager.EncipherRound(ref state);
                StateManager.XorRoundKey(roundKeys[round], state);
            }
            StateManager.EncipherRound(ref state);
            StateManager.AddRoundKey(roundKeys[Nr], state);

            return state;
        }

        public ulong[] Decode(ulong[] chipherText, ulong[] chipherKey)
        {
            var round = Nr;
            ulong[] state = new ulong[Nb];

            ulong[][] roundKeys = StateManager.KeyExpansion(chipherKey, ref state, Nb, Nk, Nr);

            Array.Copy(chipherText, state, Nb);

            StateManager.SubRoundKey(roundKeys[round], state);
            for (round = Nr - 1; round > 0; --round)
            {
                StateManager.DecipherRound(ref state);
                StateManager.XorRoundKey(roundKeys[round], state);
            }
            StateManager.DecipherRound(ref state);
            StateManager.SubRoundKey(roundKeys[0], state);

            return state;
        }

        private bool CheckBlock(BlockSize blockSize)
        {
            var keySize = (KeySize)key.Length;

            return blockSize switch
            {
                BlockSize.Bits128 => keySize == KeySize.Bits128 || keySize == KeySize.Bits256,
                BlockSize.Bits256 => keySize == KeySize.Bits256 || keySize == KeySize.Bits512,
                BlockSize.Bits512 => keySize == KeySize.Bits512,
                _ => throw new ArgumentException($"{nameof(BlockSize)} not supported: {blockSize}"),
            };
        }
    }
}
