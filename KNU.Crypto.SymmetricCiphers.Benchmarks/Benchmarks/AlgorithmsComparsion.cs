using BenchmarkDotNet.Attributes;
using KNU.Crypto.SymmetricCiphers.Common.Services;
using System.Net.Http;
using System.Threading.Tasks;

namespace KNU.Crypto.SymmetricCiphers.Benchmarks.Benchmarks
{
    public class AlgorithmsComparsion
    {
        private const int KeyLength = 128;
        private const string DataSource = "https://speed.hetzner.de/1GB.bin";

        private readonly byte[] data;

        private readonly AES.Implementation.Algorithm aes;
        private readonly Kalyna.Implementation.Algorithm kalyna;

        public AlgorithmsComparsion()
        {
            var cipherKey = RandomManager.NextBytes(KeyLength);

            aes = new AES.Implementation.Algorithm(cipherKey);
            kalyna = new Kalyna.Implementation.Algorithm(cipherKey);

            using var httpClient = new HttpClient();
            var fileResponse = Task.Run(async () => await httpClient.GetAsync(DataSource)).Result;

            data = Task.Run(async () => await fileResponse.Content.ReadAsByteArrayAsync()).Result;
        }

        [Benchmark]
        public void AESEncrypt()
        {
            aes.Encrypt(data);
        }

        [Benchmark]
        public void KalynaEncrypt()
        {
            kalyna.Encrypt(data);
        }

        [Benchmark]
        public void AESDecrypt()
        {
            aes.Decrypt(data);
        }

        [Benchmark]
        public void KalynaDecrypt()
        {
            kalyna.Decrypt(data);
        }
    }
}
