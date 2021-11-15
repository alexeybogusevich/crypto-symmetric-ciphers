namespace KNU.Crypto.SymmetricCiphers.Common.Interfaces
{
    public interface IBlock
    {
        byte[,] Bytes { get; }

        int Rows { get; }

        int Columns { get; }

        IBlock XOR(IBlock block);
    }
}
