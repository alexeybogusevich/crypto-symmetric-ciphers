using System.Linq;

namespace KNU.Crypto.SymmetricCiphers.Common.Extensions
{
    public static class ByteExtensions
    {
        public static byte LeftShift(this byte b, byte shift)
        {
            var t = (b << shift);
            return unchecked((byte)(t & 0xFF));
        }

        public static byte RightShift(this byte b, byte shift)
        {
            var t = (b >> shift);
            return unchecked((byte)(t & 0xFF));
        }

        public static byte Or(this byte a, byte b)
        {
            var t = (a | b);
            return unchecked((byte)(t & 0xFF));
        }

        public static byte And(this byte a, byte b)
        {
            var t = (a & b);
            return unchecked((byte)(t & 0xFF));
        }

        public static byte Xor(this byte a, byte b)
        {
            var t = (a ^ b);
            return unchecked((byte)(t & 0xFF));
        }

        public static byte GMul(this byte a, byte b)
        {
            byte p = 0;

            foreach (var _ in Enumerable.Range(0, 8))
            {
                if (b.And(1) != 0)
                {
                    p = p.Xor(a);
                }

                bool isReduced = a.And(0x80) != 0;

                a = a.LeftShift(1);

                if (isReduced)
                {
                    a = a.Xor(0x1B);
                }

                b = b.RightShift(1);
            }

            return p;
        }
    }
}
