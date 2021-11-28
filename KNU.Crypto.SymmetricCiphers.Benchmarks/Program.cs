using BenchmarkDotNet.Running;

namespace KNU.Crypto.SymmetricCiphers.Benchmarks
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run(typeof(Program).Assembly);
        }
    }
}
