using KNU.Crypto.SymmetricCiphers.Common.Interfaces;

namespace KNU.Crypto.SymmetricCiphers.AES.Implementation
{
    public class State : Block, IState
    {
        public State(byte[] bytes, int rows, int columns) : base(bytes, rows, columns)
        {

        }

        public IState AddRoundKey(IBlock block)
        {
            throw new System.NotImplementedException();
        }

        public IState InvMixColumns()
        {
            throw new System.NotImplementedException();
        }

        public IState InvShiftRows()
        {
            throw new System.NotImplementedException();
        }

        public IState InvSubBytes()
        {
            throw new System.NotImplementedException();
        }

        public IState MixColumns()
        {
            throw new System.NotImplementedException();
        }

        public IState ShiftRows()
        {
            throw new System.NotImplementedException();
        }

        public IState SubBytes()
        {
            throw new System.NotImplementedException();
        }
    }
}
