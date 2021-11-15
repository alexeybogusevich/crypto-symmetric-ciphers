using KNU.Crypto.SymmetricCiphers.Common.Extensions;
using KNU.Crypto.SymmetricCiphers.Common.Interfaces;

namespace KNU.Crypto.SymmetricCiphers.AES.Implementation
{
    public class State : Block, IState
    {
        public State(byte[] bytes, int rows, int columns) : base(bytes, rows, columns)
        {

        }

        public void AddRoundKey(byte[,] w, int round)
        {
            for (int i = 0; i < Rows; ++i)
            {
                for (int j = 0; j < Columns; ++j)
                {
                    bytes[i, j] = bytes[i, j].Xor(w[round * Columns + j, i]);
                }
            }
        }

        public void InvMixColumns()
        {
            throw new System.NotImplementedException();
        }

        public void InvShiftRows()
        {
            throw new System.NotImplementedException();
        }

        public void InvSubBytes()
        {
            throw new System.NotImplementedException();
        }

        public void MixColumns()
        {
            throw new System.NotImplementedException();
        }

        public void ShiftRows()
        {
            throw new System.NotImplementedException();
        }

        public void SubBytes()
        {
            throw new System.NotImplementedException();
        }
    }
}
