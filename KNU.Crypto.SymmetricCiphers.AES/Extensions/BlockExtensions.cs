using KNU.Crypto.SymmetricCiphers.Common.Interfaces;

namespace KNU.Crypto.SymmetricCiphers.AES.Extensions
{
    public static class BlockExtensions
    {
        public static byte[] ToByteArray(this IBlock block)
        {
            var length = block.Bytes.Length;
            var byteArray = new byte[length];

            var rows = block.Bytes.GetLength(0);
            var columns = block.Bytes.GetLength(1);

            for (int i = 0; i < rows; ++i)
            {
                for (int j = 0; j < columns; ++j)
                {
                    byteArray[i + rows * j] = block.Bytes[i, j];
                }
            }

            return byteArray;
        }
    }
}
