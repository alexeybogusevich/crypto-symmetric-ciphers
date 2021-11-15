using KNU.Crypto.SymmetricCiphers.Common.Interfaces;

namespace KNU.Crypto.SymmetricCiphers.AES.Implementation
{
    public class Block : IBlock
    {
        protected readonly byte[,] bytes;

        public Block(byte[] bytes, int rows, int columns)
        {
            for (int i = 0; i < rows; ++i)
            {
                for (int j = 0; j < columns; ++j)
                {
                    this.bytes[i,j] = bytes[i + rows * j];
                }
            }
        }

        public byte[,] Bytes { get => bytes; }

        public IBlock XOR(IBlock block)
        {
            throw new System.NotImplementedException();
        }
    }
}
