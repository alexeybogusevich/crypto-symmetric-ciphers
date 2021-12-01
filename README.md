# Symmetric Block Ciphers
.NET Core implementation of **AES** and **Kalyna** cryptographic algorithms that can be used to protect electronic data (see [Advanced Encryption Standard (AES)](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf), [A New Encryption Standard of Ukraine: The Kalyna Block Cipher](https://eprint.iacr.org/2015/650.pdf)).

## Classes
AES implementation can be found at **KNU.Crypto.SymmetricCiphers.AES**, Kalyna is at **KNU.Crypto.SymmetricCiphers.Kalyna**.\
Each assembly has **Data**, **Implementation** and **Parameters** namespaces.

### Data
Data contains supporting static tables (*S-box*, *Rcon* etc.) and cipher examples taken from the standards' appendixes.

```
  public static byte[] AppendixB_CipherKey => new byte[]
  {
      0x2b, 0x7e, 0x15, 0x16,
      0x28, 0xae, 0xd2, 0xa6,
      0xab, 0xf7, 0x15, 0x88,
      0x09, 0xcf, 0x4f, 0x3c
  };

  public static byte[] AppendixB_PlainText => new byte[]
  {
      0x32, 0x43, 0xf6, 0xa8,
      0x88, 0x5a, 0x30, 0x8d,
      0x31, 0x31, 0x98, 0xa2,
      0xe0, 0x37, 0x07, 0x34
  };

  public static byte[] AppendixB_EncodedText => new byte[]
  {
      0x39, 0x25, 0x84, 0x1d,
      0x02, 0xdc, 0x09, 0xfb,
      0xdc, 0x11, 0x85, 0x97,
      0x19, 0x6a, 0x0b, 0x32
  };
  ```
### Implementation
Implementation is based on **IState** interface that defines the known operations (AddRoundKey, SubBytes, MixColumns, ShiftRows) and their respective inverse analogs. \
Each algorithm has its own class that derives from **IState** and covers standard-specific details.

```
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
```

Sequential operations application can be found at **Encode** and **Decode** methods of **Alogrithm** class.

## Parameters
Each algorithm has a known set of parameters (cipher key and input lengths).\
All of them are defined at the level of the respective namespace.

```
public enum KeySize
{
    Bits128 = 128,
    Bits192 = 192,
    Bits256 = 256
}
```

# Usage
*Encryption* and *decryption* of byte arrays with the allowed values for the key length and block size can be perfomed with a simple creation of **Algorithm** instance and a call to the respective method.
```
var algorithm = new Algorithm(cipherBytes);

var encryptedBytes = algorithm.Encrypt(plainBytes);

var decryptedBytes = algorithm.Decrypt(encrypted);
```

# Algorithms speed comparsion

|        Method |             Mean |            Error |           StdDev |
|-------------- |-----------------:|-----------------:|-----------------:|
|    AESEncrypt |         30.15 us |         0.198 us |         0.175 us |
| KalynaEncrypt | 30,938,915.76 us |   612,274.856 us |   542,765.712 us |
|    AESDecrypt |         54.13 us |         0.391 us |         0.347 us |
| KalynaDecrypt | 69,843,064.00 us | 1,369,754.849 us | 1,345,282.414 us |

BenchmarkDotNet=v0.13.1, OS=Windows 10.0.19044.1348 (21H2)
AMD Ryzen 7 5700U with Radeon Graphics, 1 CPU, 16 logical and 8 physical cores
.NET SDK=6.0.100
  [Host]     : .NET Core 3.1.21 (CoreCLR 4.700.21.51404, CoreFX 4.700.21.51508), X64 RyuJIT
  DefaultJob : .NET Core 3.1.21 (CoreCLR 4.700.21.51404, CoreFX 4.700.21.51508), X64 RyuJIT
