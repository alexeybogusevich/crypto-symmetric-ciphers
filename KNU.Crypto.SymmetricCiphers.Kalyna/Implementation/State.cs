using KNU.Crypto.SymmetricCiphers.Common.Interfaces;
using System;

namespace KNU.Crypto.SymmetricCiphers.Kalyna.Implementation
{
    public class State : IState
    {
        public State(ulong[] bytes)
        {

        }

        public void AddRoundKey(byte[,] w, int round)
        {
            throw new NotImplementedException();
        }

        public void SubBytes()
        {
            var bytesCopy = (byte[,])bytes.Clone();

            for (int c = 0; c < Columns; ++c)
            {
                state[c] = sboxes_enc[0][s[c] & 0x00000000000000FFUL] |
                                ((ulong)sboxes_enc[1][(s[c] & 0x000000000000FF00UL) >> 8] << 8) |
                                ((ulong)sboxes_enc[2][(s[c] & 0x0000000000FF0000UL) >> 16] << 16) |
                                ((ulong)sboxes_enc[3][(s[c] & 0x00000000FF000000UL) >> 24] << 24) |
                                ((ulong)sboxes_enc[0][(s[c] & 0x000000FF00000000UL) >> 32] << 32) |
                                ((ulong)sboxes_enc[1][(s[c] & 0x0000FF0000000000UL) >> 40] << 40) |
                                ((ulong)sboxes_enc[2][(s[c] & 0x00FF000000000000UL) >> 48] << 48) |
                                ((ulong)sboxes_enc[3][(s[c] & 0xFF00000000000000UL) >> 56] << 56);
            }
        }

        public void ShiftRows()
        {
            throw new NotImplementedException();
        }

        public void MixColumns()
        {
            throw new NotImplementedException();
        }

        public void InvSubBytes()
        {
            throw new NotImplementedException();
        }

        public void InvShiftRows()
        {
            throw new NotImplementedException();
        }

        public void InvMixColumns()
        {
            throw new NotImplementedException();
        }
    }
}
