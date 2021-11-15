namespace KNU.Crypto.SymmetricCiphers.Common.Interfaces
{
    public interface IAlgorithm
    {
        byte[] Encode(byte[] plainBytes);

        byte[] Decode(byte[] cipherBytes);
    }
}
