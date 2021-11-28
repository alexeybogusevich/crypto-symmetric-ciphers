using KNU.Crypto.SymmetricCiphers.Common.Interfaces;
using KNU.Crypto.SymmetricCiphers.Kalyna.Data;
using System.Collections.Generic;

namespace KNU.Crypto.SymmetricCiphers.Kalyna.Implementation
{
    public class Algorithm : IAlgorithm
    {
        /// <summary>
        /// Cipher Key.
        /// </summary>
        private readonly byte[] cipherKey;

        private List<State> RoundKeys { get; } = new List<State>();


        public Algorithm(byte[] key)
        {
            this.cipherKey = key;
        }


        public byte[] Encrypt(byte[] plainBytes)
        {
            if (RoundKeys.Count == 0)
                KeyExpansion(cipherKey);

            var state = new State(plainBytes);
            state.AddRoundKey(RoundKeys[0].Bytes);

            for (int i = 1; i <= 9; i++)
            {
                state.SubBytes(Tables.Π);
                state.ShiftRows();
                state.MixColumns(Tables.Mds);
                state.Xor(RoundKeys[i].Bytes);
            }

            state.SubBytes(Tables.Π);
            state.ShiftRows();
            state.MixColumns(Tables.Mds);
            state.AddRoundKey(RoundKeys[10].Bytes);

            return state.Bytes.ToArray();
        }

        public byte[] Decrypt(byte[] plainBytes)
        {
            if (RoundKeys.Count == 0)
                KeyExpansion(cipherKey);

            var state = new State(plainBytes);

            state.SubRoundKey(RoundKeys[10].Bytes);
            state.MixColumns(Tables.MdsRev);
            state.ShiftRowsRev();
            state.SubBytes(Tables.ΠRev);

            for (int i = 9; 1 <= i; --i)
            {
                state.Xor(RoundKeys[i].Bytes);
                state.MixColumns(Tables.MdsRev);
                state.ShiftRowsRev();
                state.SubBytes(Tables.ΠRev);
            }

            state.SubRoundKey(RoundKeys[0].Bytes);

            return state.Bytes.ToArray();
        }

        private State GenerateKt(byte[] key)
        {
            var kt = new State
            {
                Bytes = new List<byte>
                {
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5
                }
            };

            kt.AddRoundKey(key);

            kt.SubBytes(Tables.Π);
            kt.ShiftRows();
            kt.MixColumns(Tables.Mds);

            kt.Xor(key);

            kt.SubBytes(Tables.Π);
            kt.ShiftRows();
            kt.MixColumns(Tables.Mds);

            kt.AddRoundKey(key);

            kt.SubBytes(Tables.Π);
            kt.ShiftRows();
            kt.MixColumns(Tables.Mds);

            return kt;
        }

        private IEnumerable<State> KeyExpansion(byte[] key)
        {
            for (int i = 0; i <= 10; i++)
                RoundKeys.Add(new State());

            var kt = GenerateKt(key);

            for (int i = 0; i <= 10; i += 2)
            {
                var roundKey = RoundKeys[i];
                roundKey.Bytes = new List<byte>(Tables.V);
                roundKey.ShiftLeft(i / 2);

                var keyCopy = new State(key);
                keyCopy.RotateRight(32 * i);

                roundKey.AddRoundKey(kt.Bytes);
                var copy = new State(roundKey.Bytes);

                roundKey.AddRoundKey(keyCopy.Bytes);

                roundKey.SubBytes(Tables.Π);
                roundKey.ShiftRows();
                roundKey.MixColumns(Tables.Mds);

                roundKey.Xor(copy.Bytes);

                roundKey.SubBytes(Tables.Π);
                roundKey.ShiftRows();
                roundKey.MixColumns(Tables.Mds);

                roundKey.AddRoundKey(copy.Bytes);
                RoundKeys[i] = roundKey;
            }

            for (var i = 1; i <= 9; i += 2)
            {
                RoundKeys[i].Bytes = RoundKeys[i - 1].Bytes;
                RoundKeys[i].RotateLeft(56);
            }

            return RoundKeys;
        }
    }
}
