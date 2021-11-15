namespace KNU.Crypto.SymmetricCiphers.Common.Interfaces
{
    public interface IState 
    {
        void AddRoundKey(byte[,] w, int round);

        void SubBytes();

        void InvSubBytes();

        void ShiftRows();

        void InvShiftRows();

        void MixColumns();

        void InvMixColumns();
    }
}
