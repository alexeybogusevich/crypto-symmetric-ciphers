namespace KNU.Crypto.SymmetricCiphers.Common.Interfaces
{
    public interface IState 
    {
        IState AddRoundKey(IBlock block);

        IState SubBytes();

        IState InvSubBytes();

        IState ShiftRows();

        IState InvShiftRows();

        IState MixColumns();

        IState InvMixColumns();
    }
}
