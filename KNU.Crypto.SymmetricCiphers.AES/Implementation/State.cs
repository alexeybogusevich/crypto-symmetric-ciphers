using KNU.Crypto.SymmetricCiphers.AES.Data;
using KNU.Crypto.SymmetricCiphers.Common.Extensions;
using KNU.Crypto.SymmetricCiphers.Common.Interfaces;
using System.Text;

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
                    var l = round * Columns;
                    bytes[i, j] = bytes[i, j].Xor(w[l + j, i]);
                }
            }
        }

        public void SubBytes()
        {
            for (int r = 0; r < Rows; ++r)
            {
                for (int c = 0; c < Columns; ++c)
                {
                    bytes[r, c] = Tables.Sbox[bytes[r, c].RightShift(4), bytes[r, c].And(0x0f)];
                }
            }
        }

        public void ShiftRows()
        {
            var bytesCopy = (byte[,])bytes.Clone();

            for (int r = 1; r < Rows; ++r)
            {
                for (int c = 0; c < Columns; ++c)
                {
                    bytes[r, c] = bytesCopy[r, (c + r) % Columns];
                }
            }
        }

        public void MixColumns()
        {
            var bytesCopy = (byte[,])bytes.Clone();

            for (int c = 0; c < Columns; ++c)
            {
                bytes[0, c] = 
                    bytesCopy[0, c].GMul(0x02)
                    .Xor(bytesCopy[1, c].GMul(0x03))
                    .Xor(bytesCopy[2, c])
                    .Xor(bytesCopy[3, c]);

                bytes[1, c] =
                    bytesCopy[0, c]
                    .Xor(bytesCopy[1, c].GMul(0x02))
                    .Xor(bytesCopy[2, c].GMul(0x03))
                    .Xor(bytesCopy[3, c]);

                bytes[2, c] =
                    bytesCopy[0, c]
                    .Xor(bytesCopy[1, c])
                    .Xor(bytesCopy[2, c].GMul(0x02))
                    .Xor(bytesCopy[3, c].GMul(0x03));

                bytes[3, c] =
                    bytesCopy[0, c].GMul(0x03)
                    .Xor(bytesCopy[1, c])
                    .Xor(bytesCopy[2, c])
                    .Xor(bytesCopy[3, c].Xor(0x02));
            }
        }

        public void InvSubBytes()
        {
            for (int r = 0; r < Rows; ++r)
            {
                for (int c = 0; c < Columns; ++c)
                {
                    bytes[r, c] = Tables.InvSbox[bytes[r, c].RightShift(4), bytes[r, c].And(0x0f)];
                }
            }
        }

        public void InvShiftRows()
        {
            var bytesCopy = (byte[,])bytes.Clone();

            for (int r = 1; r < Rows; ++r)
            {
                for (int c = 0; c < Columns; ++c)
                {
                    bytes[r, (c + r) % Columns] = bytesCopy[r, c];
                }
            }
        }

        public void InvMixColumns()
        {
            var bytesCopy = (byte[,])bytes.Clone();

            for (int c = 0; c < Columns; ++c)
            {
                bytes[0, c] =
                    bytesCopy[0, c].GMul(0x0e)
                    .Xor(bytesCopy[1, c].GMul(0x0b))
                    .Xor(bytesCopy[2, c].GMul(0x0d))
                    .Xor(bytesCopy[3, c].GMul(0x09));

                bytes[1, c] =
                    bytesCopy[0, c].GMul(0x09)
                    .Xor(bytesCopy[1, c].GMul(0x0e))
                    .Xor(bytesCopy[2, c].GMul(0x0b))
                    .Xor(bytesCopy[3, c].GMul(0x0d));

                bytes[2, c] =
                    bytesCopy[0, c].GMul(0x0d)
                    .Xor(bytesCopy[1, c].GMul(0x09))
                    .Xor(bytesCopy[2, c].GMul(0x0e))
                    .Xor(bytesCopy[3, c].GMul(0x0b));

                bytes[3, c] =
                    bytesCopy[0, c].GMul(0x0b)
                    .Xor(bytesCopy[1, c].GMul(0x0d))
                    .Xor(bytesCopy[2, c].GMul(0x09))
                    .Xor(bytesCopy[3, c].GMul(0x0e));
            }
        }

        public override string ToString()
        {
            var sb = new StringBuilder().AppendLine();

            for (int r = 0; r < Rows; ++r)
            {
                for (int c = 0; c < Columns; ++c)
                {
                    sb.Append($"{bytes[r, c].ToString("X2")} ");
                }

                sb.AppendLine();
            }

            return sb.ToString();
        }
    }
}
