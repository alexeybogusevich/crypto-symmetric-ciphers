using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace KNU.Crypto.SymmetricCiphers.Kalyna.Implementation
{
    public class State 
    {
        public List<byte> Bytes { get; set; } = new List<byte>();

        public State() { }

        public State(IEnumerable<byte> bytes)
        {
            Bytes = new List<byte>(bytes);
        }

        public void AddRoundKey(IEnumerable<byte> bytes)
        {
            const int n = 8;
            for (var i = 0; i < 16; i += n)
            {
                var dataBi = new BigInteger(bytes.Where((d, idx) => i <= idx && idx < i + n).ToArray());

                dataBi += new BigInteger(bytes.Where((d, idx) => i <= idx && idx < i + n).ToArray());
                var newData = dataBi.ToByteArray();

                for (var j = 0; j < n; j++)
                    Bytes[i + j] = j < newData.Length ? newData[j] : (byte)0;
            }
        }

        public void SubRoundKey(IEnumerable<byte> bytes)
        {
            const int n = 8;
            for (var i = 0; i < 16; i += n)
            {
                var dataBi = new BigInteger(Bytes.Where((d, idx) => i <= idx && idx < i + n).ToArray());
                dataBi -= new BigInteger(bytes.Where((d, idx) => i <= idx && idx < i + n).ToArray());
                var newData = dataBi.ToByteArray();
                for (var j = 0; j < n; j++)
                    Bytes[i + j] = j < newData.Length ? newData[j] : (byte)0;
            }
        }

        public void RotateRight(int i)
        {
            var bi = new BigInteger(Bytes.ToArray());
            bi = (bi >> i % 128) + (bi << (128 - i % 128));
            Bytes = new List<byte>(bi.ToByteArray().Where((t, idx) => idx < 16));
        }

        public void RotateLeft(int i)
        {
            var bi = new BigInteger(Bytes.ToArray());
            bi = (bi << i % 128) + (bi >> (128 - i % 128));
            Bytes = new List<byte>(bi.ToByteArray().Where((t, idx) => idx < 16));
        }

        public void ShiftLeft(int i)
        {
            var bi = new BigInteger(Bytes.ToArray());
            bi <<= i;
            Bytes = new List<byte>(bi.ToByteArray());
        }

        public void SubBytes(byte[][][] table)
        {
            var trump = 0;
            for (var i = Bytes.Count - 1; 0 <= i; --i)
            {
                var d = Bytes[i];
                var upper = (d & 0xF0) >> 4;
                var lower = d & 0x0F;
                Bytes[i] = table[trump % 4][upper][lower];
                trump = ++trump % 4;
            }
        }

        private void ShiftBytesPair(int i1, int i2)
        {
            var buf = Bytes[i1];
            Bytes[i1] = Bytes[i2];
            Bytes[i2] = buf;
        }

        public void ShiftRows()
        {
            for (var i = 11; 8 <= i; --i)
                ShiftBytesPair(i, i - 8);
        }

        public void ShiftRowsRev()
        {
            for (var i = 11; 8 <= i; --i)
                ShiftBytesPair(i - 8, i);
        }

        public void MixColumns(byte[][] table)
        {
            var dataCopy = new List<byte>(Bytes);

            var trump = Bytes.Count - 1;
            for (var row = 0; row < 8; row++)
            {
                byte sum = 0;
                var hillary = Bytes.Count - 1;
                for (var h = 0; h < 8; h++)
                {
                    sum ^= Gmul(dataCopy[hillary], table[row][h]);
                    hillary--;
                }
                Bytes[trump] = sum;
                trump--;
            }

            trump = Bytes.Count - 1 - 8;
            for (var row = 0; row < 8; row++)
            {
                byte sum = 0;
                var hillary = Bytes.Count - 1 - 8;
                for (var h = 0; h < 8; h++)
                {
                    sum ^= Gmul(dataCopy[hillary], table[row][h]);
                    hillary--;
                }
                Bytes[trump] = sum;
                trump--;
            }
        }

        public void Xor(IEnumerable<byte> bytes)
        {
            for (var i = 0; i < Bytes.Count; i++)
                Bytes[i] ^= bytes.ElementAt(i);
        }

        private static byte Gmul(int a, int b)
        {
            byte p = 0; /* the product of the multiplication */
            while (b != 0)
            {
                if ((b & 1) == 1) /* if b is odd, then add the corresponding a to p (final product = sum of all a's corresponding to odd b's) */
                    p ^= (byte)a; /* since we're in GF(2^m), addition is an XOR */

                if ((a & 0x80) == 0x80) /* GF modulo: if a >= 128, then it will overflow when shifted left, so reduce */
                    a = (a << 1) ^ 0x11d; /* XOR with the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0b1_0001_1011) -- you can change it but it must be irreducible */
                else
                    a <<= 1; /* equivalent to a*2 */
                b >>= 1; /* equivalent to b // 2 */
            }
            return p;
        }
    }
}

