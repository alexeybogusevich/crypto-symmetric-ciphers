using KNU.Crypto.SymmetricCiphers.Common.Interfaces;
using System;
using System.Diagnostics.CodeAnalysis;

namespace KNU.Crypto.SymmetricCiphers.Common.Models
{
    public class Block : IBlock, IEquatable<Block>
    {
        protected readonly byte[,] bytes;

        public Block(byte[] bytes, int rows, int columns)
        {
            this.bytes = new byte[rows, columns];

            for (int i = 0; i < rows; ++i)
            {
                for (int j = 0; j < columns; ++j)
                {
                    this.bytes[i, j] = bytes[i + rows * j];
                }
            }
        }

        public byte[,] Bytes => bytes;

        public int Rows => bytes.GetLength(0);

        public int Columns => bytes.GetLength(1);

        public bool Equals([AllowNull] Block other)
        {
            if (other is null)
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            if (GetType() != other.GetType())
            {
                return false;
            }

            if (Rows != other.Rows || Columns != other.Columns)
            {
                return false;
            }

            for (int i = 0; i < Rows; ++i)
            {
                for (int j = 0; j < Columns; ++j)
                {
                    if (bytes[i, j] != other.Bytes[i, j])
                    {
                        return false;
                    }
                }
            }

            return true;
        }
    }
}
