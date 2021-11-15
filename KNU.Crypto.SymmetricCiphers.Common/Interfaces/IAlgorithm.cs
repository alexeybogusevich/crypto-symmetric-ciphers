namespace KNU.Crypto.SymmetricCiphers.Common.Interfaces
{
    public interface IAlgorithm
    {
        byte[] Encode(byte[] plainText);

        byte[] Decode(byte[] cipherText);
    }
}
