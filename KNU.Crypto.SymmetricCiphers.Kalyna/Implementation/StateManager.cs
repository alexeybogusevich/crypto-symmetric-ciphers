using KNU.Crypto.SymmetricCiphers.Common.Extensions;
using KNU.Crypto.SymmetricCiphers.Kalyna.Data;
using System;

namespace KNU.Crypto.SymmetricCiphers.Kalyna.Implementation
{
    public class StateManager
    {
        public static void SubBytes(ulong[] state, int nb)
        {
            ulong[] s = (ulong[])state.Clone();
            for (int i = 0; i < nb; ++i)
            {
                state[i] = Tables.SBoxes[0][s[i] & 0x00000000000000FFUL] |
                            ((ulong)Tables.SBoxes[1][(s[i] & 0x000000000000FF00UL) >> 8] << 8) |
                            ((ulong)Tables.SBoxes[2][(s[i] & 0x0000000000FF0000UL) >> 16] << 16) |
                            ((ulong)Tables.SBoxes[3][(s[i] & 0x00000000FF000000UL) >> 24] << 24) |
                            ((ulong)Tables.SBoxes[0][(s[i] & 0x000000FF00000000UL) >> 32] << 32) |
                            ((ulong)Tables.SBoxes[1][(s[i] & 0x0000FF0000000000UL) >> 40] << 40) |
                            ((ulong)Tables.SBoxes[2][(s[i] & 0x00FF000000000000UL) >> 48] << 48) |
                            ((ulong)Tables.SBoxes[3][(s[i] & 0xFF00000000000000UL) >> 56] << 56);
            }
        }

        public static void InvSubBytes(ulong[] state, int nb)
        {
            ulong[] s = (ulong[])state.Clone();
            for (int i = 0; i < nb; ++i)
            {
                state[i] = Tables.InvSBoxes[0][s[i] & 0x00000000000000FFUL] |
                            ((ulong)Tables.InvSBoxes[1][(s[i] & 0x000000000000FF00UL) >> 8] << 8) |
                            ((ulong)Tables.InvSBoxes[2][(s[i] & 0x0000000000FF0000UL) >> 16] << 16) |
                            ((ulong)Tables.InvSBoxes[3][(s[i] & 0x00000000FF000000UL) >> 24] << 24) |
                            ((ulong)Tables.InvSBoxes[0][(s[i] & 0x000000FF00000000UL) >> 32] << 32) |
                            ((ulong)Tables.InvSBoxes[1][(s[i] & 0x0000FF0000000000UL) >> 40] << 40) |
                            ((ulong)Tables.InvSBoxes[2][(s[i] & 0x00FF000000000000UL) >> 48] << 48) |
                            ((ulong)Tables.InvSBoxes[3][(s[i] & 0xFF00000000000000UL) >> 56] << 56);
            }
        }

        public static void ShiftRows(ref ulong[] lstate, int nb)
        {
            int shift = -1;

            byte[] state = WordsToBytes(lstate);
            byte[] nstate = new byte[nb * sizeof(ulong) / sizeof(byte)];

            for (int row = 0; row < sizeof(ulong); ++row)
            {
                if (row % (sizeof(ulong) / nb) == 0)
                    shift += 1;
                for (int col = 0; col < nb; ++col)
                {
                    nstate[row + sizeof(ulong) * ((col + shift) % nb)] = state[row + sizeof(ulong) * col];
                }
            }

            lstate = BytesToWords(nstate);
        }

        public static void InvShiftRows(ref ulong[] lstate, int nb)
        {
            int shift = -1;

            byte[] state = WordsToBytes(lstate);
            byte[] nstate = new byte[nb * sizeof(ulong) / sizeof(byte)];

            for (int row = 0; row < sizeof(ulong); ++row)
            {
                if (row % (sizeof(ulong) / nb) == 0)
                    shift += 1;
                for (int col = 0; col < nb; ++col)
                {
                    nstate[row + sizeof(ulong) * col] = state[row + sizeof(ulong) * ((col + shift) % nb)];
                }
            }

            lstate = BytesToWords(nstate);
        }

        public static void MixColumns(ref ulong[] lstate, int nb)
        {
            int row, b;
            byte product;
            ulong result;
            byte[] state = WordsToBytes(lstate);

            for (int col = 0; col < nb; ++col)
            {
                result = 0;
                for (row = sizeof(ulong) - 1; row >= 0; --row)
                {
                    product = 0;
                    for (b = sizeof(ulong) - 1; b >= 0; --b)
                    {
                        product ^= state[b + sizeof(ulong) * col].GMul(Tables.MDS[row][b]);
                    }
                    result |= (ulong)product << (row * sizeof(ulong));
                }
                lstate[col] = result;
            }
        }

        public static void InvMixColumns(ref ulong[] lstate, int nb)
        {
            int row, b;
            byte product;
            ulong result;
            byte[] state = WordsToBytes(lstate);

            for (int col = 0; col < nb; ++col)
            {
                result = 0;
                for (row = sizeof(ulong) - 1; row >= 0; --row)
                {
                    product = 0;
                    for (b = sizeof(ulong) - 1; b >= 0; --b)
                    {
                        product ^= state[b + sizeof(ulong) * col].GMul(Tables.InvMDS[row][b]);
                    }
                    result |= (ulong)product << (row * sizeof(ulong));
                }
                lstate[col] = result;
            }
        }

        public static void XorRoundKey(ulong[] state, ulong[] value)
        {
            for (int i = 0; i < state.Length; ++i)
            {
                state[i] ^= value[i];
            }
        }

        public static void AddRoundKey(ulong[] state, ulong[] value)
        {
            for (int i = 0; i < state.Length; ++i)
            {
                state[i] += value[i];
            }
        }

        public static void SubRoundKey(ulong[] state, ulong[] value)
        {
            for (int i = 0; i < state.Length; ++i)
            {
                state[i] += value[i];
            }
        }

        private static byte[] WordsToBytes(ulong[] words)
        {
            bool isLittleEndian = true;
            byte[] data = new byte[words.Length * sizeof(ulong) / sizeof(byte)];
            int offset = 0;

            foreach (long value in words)
            {
                byte[] buffer = BitConverter.GetBytes(value);
                if (BitConverter.IsLittleEndian != isLittleEndian)
                {
                    Array.Reverse(buffer);
                }
                buffer.CopyTo(data, offset);
                offset += 8;
            }

            return data;
        }

        public static void EncipherRound(ref ulong[] state)
        {
            SubBytes(state, state.Length);
            ShiftRows(ref state, state.Length);
            MixColumns(ref state, state.Length);
        }

        public static void DecipherRound(ref ulong[] state)
        {
            InvMixColumns(ref state, state.Length);
            InvShiftRows(ref state, state.Length);
            InvSubBytes(state, state.Length);
        }

        public static void KeyExpandKt(ulong[] key, int nb, int nk, ref ulong[] lstate, ref ulong[] kt)
        {
            ulong[] k0 = new ulong[nb];
            ulong[] k1 = new ulong[nb];

            lstate.Initialize();

            lstate[0] += (ulong)(nb + nk + 1);

            if (nb == nk)
            {
                Array.Copy(key, k0, nb);
                Array.Copy(key, k1, nb);
            }
            else
            {
                Array.Copy(key, k0, nb);
                Array.Copy(key, nb, k1, 0, nb);
            }

            AddRoundKey(k0, lstate);
            EncipherRound(ref lstate);
            XorRoundKey(k1, lstate);
            EncipherRound(ref lstate);
            AddRoundKey(k0, lstate);
            EncipherRound(ref lstate);

            Array.Copy(lstate, kt, nb);
        }

        public static void KeyExpandEven(
            ulong[] key, int nb, int nk, int nr, ref ulong[] lstate, ref ulong[] kt, ref ulong[][] roundKeys)
        {
            ulong[] initial_data = new ulong[nk];
            ulong[] kt_round = new ulong[nb];
            ulong[] tmv = new ulong[nb];
            int round = 0;

            Array.Copy(key, initial_data, nk);

            for (int i = 0; i < nb; ++i)
            {
                tmv[i] = 0x0001000100010001;
            }

            while (true)
            {
                Array.Copy(kt, lstate, nb);
                AddRoundKey(tmv, lstate);
                Array.Copy(lstate, kt_round, nb);
                Array.Copy(initial_data, lstate, nb);

                AddRoundKey(kt_round, lstate);
                EncipherRound(ref lstate);
                XorRoundKey(kt_round, lstate);
                EncipherRound(ref lstate);
                AddRoundKey(kt_round, lstate);

                Array.Copy(lstate, roundKeys[round], nb);

                if (nr == round)
                    break;

                if (nk != nb)
                {
                    round += 2;

                    ShiftLeft(tmv);
                    Array.Copy(kt, lstate, nb);
                    AddRoundKey(tmv, lstate);
                    Array.Copy(lstate, kt_round, nb);
                    Array.Copy(initial_data, nb, lstate, 0, nb);
                    AddRoundKey(kt_round, lstate);
                    EncipherRound(ref lstate);
                    XorRoundKey(kt_round, lstate);
                    EncipherRound(ref lstate);
                    AddRoundKey(kt_round, lstate);

                    Array.Copy(lstate, roundKeys[round], nb);

                    if (nr == round)
                        break;
                }

                round += 2;
                ShiftLeft(tmv);
                Rotate(initial_data);
            }
        }

        private static void Rotate(ulong[] state)
        {
            ulong temp = state[0];
            for (int i = 1; i < state.Length; ++i)
            {
                state[i - 1] = state[i];
            }
            state[state.Length - 1] = temp;
        }

        private static void ShiftLeft(ulong[] state)
        {
            for (int i = 0; i < state.Length; ++i)
            {
                state[i] <<= 1;
            }
        }

        private static void RotateLeft(ref ulong[] state)
        {
            int rotateBytes = 2 * state.Length + 3;
            int bytesNum = state.Length * (sizeof(ulong) / sizeof(byte));

            byte[] bytes = WordsToBytes(state);
            byte[] buffer = new byte[rotateBytes];

            Array.Copy(bytes, buffer, rotateBytes);
            Array.ConstrainedCopy(bytes, rotateBytes, bytes, 0, bytesNum - rotateBytes);
            Array.Copy(buffer, 0, bytes, bytesNum - rotateBytes, rotateBytes);

            state = BytesToWords(bytes);
        }

        private static void KeyExpandOdd(int nb, int nr, ref ulong[][] roundKeys)
        {
            for (int i = 1; i < nr; i += 2)
            {
                Array.Copy(roundKeys[i - 1], roundKeys[i], nb);
                RotateLeft(ref roundKeys[i]);
            }
        }

        public static ulong[][] KeyExpansion(ulong[] key, ref ulong[] lstate, int nb, int nk, int nr)
        {
            ulong[] kt = new ulong[nb];
            ulong[][] roundKeys = new ulong[nr + 1][];

            for (int r = 0; r < roundKeys.Length; r++)
            {
                roundKeys[r] = new ulong[nb];
            }

            KeyExpandKt(key, nb, nk, ref lstate, ref kt);
            KeyExpandEven(key, nb, nk, nr, ref lstate, ref kt, ref roundKeys);
            KeyExpandOdd(nb, nr, ref roundKeys);

            return roundKeys;
        }

        private static ulong[] BytesToWords(byte[] bytes)
        {
            ulong[] words = new ulong[bytes.Length / 8];

            for (int i = 0; i < bytes.Length / 8; i++)
            {
                words[i] = BitConverter.ToUInt64(bytes, 8 * i);
            }

            return words;
        }
    }
}

