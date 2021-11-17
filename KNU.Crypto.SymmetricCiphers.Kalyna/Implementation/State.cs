using KNU.Crypto.SymmetricCiphers.Common.Interfaces;
using KNU.Crypto.SymmetricCiphers.Common.Models;
using System;

namespace KNU.Crypto.SymmetricCiphers.Kalyna.Implementation
{
    public class State : Block, IState
    {
        public State(byte[] bytes, int rows, int columns) : base(bytes, rows, columns) { }

        public void AddRoundKey(byte[,] w, int round)
        {
            throw new NotImplementedException();
        }

        public void InvMixColumns()
        {
            throw new NotImplementedException();
        }

        public void InvShiftRows()
        {
            throw new NotImplementedException();
        }

        public void InvSubBytes()
        {
            throw new NotImplementedException();
        }

        public void MixColumns()
        {
            throw new NotImplementedException();
        }

        public void ShiftRows()
        {
            throw new NotImplementedException();
        }

        public void SubBytes()
        {
            throw new NotImplementedException();
        }
    }
}
