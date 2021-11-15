namespace KNU.Crypto.SymmetricCiphers.Common.Interfaces
{
    public interface IBlock
    {
        byte[,] Bytes { get; }

        IBlock XOR(IBlock block);
    }
}
