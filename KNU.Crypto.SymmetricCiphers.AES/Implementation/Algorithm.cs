using KNU.Crypto.SymmetricCiphers.AES.Data;
using KNU.Crypto.SymmetricCiphers.AES.Extensions;
using KNU.Crypto.SymmetricCiphers.Common.Extensions;
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
                    throw new ArgumentException($"KeySize not supported: {key.Length}");
            }

            this.key = new byte[Nk * 4];
            key.CopyTo(this.key, 0);

            KeyExpansion(key);
        }

        public byte[] Encode(byte[] plainBytes)
        {
            var state = new State(plainBytes, 4, Nb);
            Console.WriteLine(state);

            state.AddRoundKey(w, 0);
            Console.WriteLine(nameof(State.AddRoundKey));
            Console.WriteLine(state);

            for (int round = 1; round < Nr; ++round)
            {
                state.SubBytes();
                Console.WriteLine(nameof(State.SubBytes));
                Console.WriteLine(state);

                state.ShiftRows();
                Console.WriteLine(nameof(State.ShiftRows));
                Console.WriteLine(state);

                state.MixColumns();
                Console.WriteLine(nameof(State.MixColumns));
                Console.WriteLine(state);

                state.AddRoundKey(w, round);
                Console.WriteLine(nameof(State.AddRoundKey));
                Console.WriteLine(state);
            }

            state.SubBytes();
            Console.WriteLine(nameof(State.SubBytes));
            Console.WriteLine(state);

            state.ShiftRows();
            Console.WriteLine(nameof(State.ShiftRows));
            Console.WriteLine(state);

            state.AddRoundKey(w, Nr);
            Console.WriteLine(nameof(State.AddRoundKey));
            Console.WriteLine(state);

            return state.ToByteArray();
        }

        public byte[] Decode(byte[] cipherBytes)
        {
            var state = new State(cipherBytes, 4, Nb);
            Console.WriteLine(state);

            state.AddRoundKey(w, Nr);
            Console.WriteLine(nameof(State.AddRoundKey));
            Console.WriteLine(state);

            for (int round = Nr - 1; round > 0; --round)
            {
                state.InvShiftRows();
                Console.WriteLine(nameof(State.InvShiftRows));
                Console.WriteLine(state);

                state.InvSubBytes();
                Console.WriteLine(nameof(State.InvSubBytes));
                Console.WriteLine(state);

                state.AddRoundKey(w, round);
                Console.WriteLine(nameof(State.AddRoundKey));
                Console.WriteLine(state);

                state.InvMixColumns();
                Console.WriteLine(nameof(State.InvMixColumns));
                Console.WriteLine(state);
            }

            state.InvShiftRows();
            Console.WriteLine(nameof(State.InvShiftRows));
            Console.WriteLine(state);

            state.InvSubBytes();
            Console.WriteLine(nameof(State.InvSubBytes));
            Console.WriteLine(state);

            state.AddRoundKey(w, 0);
            Console.WriteLine(nameof(State.AddRoundKey));
            Console.WriteLine(state);

            return state.ToByteArray();
        }

        private void KeyExpansion(byte[] key)
        {
            w = new byte[Nb * (Nr + 1), 4];

            for (int i = 0; i < Nk; ++i)
            {
                w[i, 0] = key[4 * i];
                w[i, 1] = key[4 * i + 1];
                w[i, 2] = key[4 * i + 2];
                w[i, 3] = key[4 * i + 3];
            }

            var temp = new byte[4];

            for (int i = Nk; i < Nb * (Nr + 1); ++i)
            {
                temp[0] = w[i - 1, 0]; 
                temp[1] = w[i - 1, 1];
                temp[2] = w[i - 1, 2]; 
                temp[3] = w[i - 1, 3];

                if (i % Nk == 0)
                {
                    temp = SubWord(RotWord(temp));

                    temp[0] = temp[0].Xor(Tables.Rcon[i / Nk, 0]);
                    temp[1] = temp[1].Xor(Tables.Rcon[i / Nk, 1]);
                    temp[2] = temp[2].Xor(Tables.Rcon[i / Nk, 2]);
                    temp[3] = temp[3].Xor(Tables.Rcon[i / Nk, 3]);
                }
                else if (Nk > 6 && (i % Nk == 4))
                {
                    temp = SubWord(temp);
                }

                w[i, 0] = w[i - Nk, 0].Xor(temp[0]);
                w[i, 1] = w[i - Nk, 1].Xor(temp[1]);
                w[i, 2] = w[i - Nk, 2].Xor(temp[2]);
                w[i, 3] = w[i - Nk, 3].Xor(temp[3]);
            }
        }

        private byte[] SubWord(byte[] word)
        {
            var result = new byte[4];

            result[0] = Tables.Sbox[word[0].RightShift(4), word[0].And(0x0f)];
            result[1] = Tables.Sbox[word[1].RightShift(4), word[1].And(0x0f)];
            result[2] = Tables.Sbox[word[2].RightShift(4), word[2].And(0x0f)];
            result[3] = Tables.Sbox[word[3].RightShift(4), word[3].And(0x0f)];

            return result;
        }

        private byte[] RotWord(byte[] word)
        {
            var result = new byte[4];

            result[0] = word[1];
            result[1] = word[2];
            result[2] = word[3];
            result[3] = word[0];

            return result;
        }
    }
}
