namespace KNU.Crypto.SymmetricCiphers.Common.Interfaces
{
    public interface IAlgorithm
    {
        byte[] Encrypt(byte[] plainBytes);

        byte[] Decrypt(byte[] cipherBytes);
    }
}
