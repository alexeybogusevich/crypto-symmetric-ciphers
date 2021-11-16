using KNU.Crypto.SymmetricCiphers.Common.Interfaces;

namespace KNU.Crypto.SymmetricCiphers.AES.Implementation
{
    public class Block : IBlock
    {
        protected readonly byte[,] bytes;

        public Block(byte[] bytes, int rows, int columns)
        {
            this.bytes = new byte[rows, columns];

            for (int i = 0; i < rows; ++i)
            {
                for (int j = 0; j < columns; ++j)
                {
                    this.bytes[i,j] = bytes[i + rows * j];
                }
            }
        }

        public byte[,] Bytes => bytes;

        public int Rows => bytes.GetLength(0);
        public int Columns => bytes.GetLength(1);

        public IBlock XOR(IBlock block)
        {
            throw new System.NotImplementedException();
        }
    }
}
