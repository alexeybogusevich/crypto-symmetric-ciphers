using FluentAssertions;
using KNU.Crypto.SymmetricCiphers.AES.Data;
using KNU.Crypto.SymmetricCiphers.AES.Implementation;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace KNU.Crypto.SymmetricCiphers.AES.Tests.Implementation
{
    [TestClass]
    public class AlgorithmTests
    {
        [TestClass]
        public class AES128
        {
            [TestMethod]
            public void Encode_AppendixB_EncodedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixB_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixB_PlainText;
                var expectedEncodedBytes = Examples.AppendixB_EncodedText;

                // Act
                var encodedBytes = algorithm.Encode(plainBytes);

                // Assert
                encodedBytes.Should().BeEquivalentTo(expectedEncodedBytes);
            }

            [TestMethod]
            public void Decode_AppendixB_DecodedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixB_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var encodedBytes = Examples.AppendixB_EncodedText;
                var expectedDecodedBytes = Examples.AppendixB_PlainText;

                // Act
                var decodedBytes = algorithm.Decode(encodedBytes);

                // Assert
                decodedBytes.Should().BeEquivalentTo(expectedDecodedBytes);
            }

            [TestMethod]
            public void EncodeDecode_AppendixB_EncodedDecodedMatch()
            {
                // Arrange
                var cipherBytes = Examples.AppendixB_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixB_PlainText;

                // Act
                var encodedBytes = algorithm.Encode(plainBytes);
                var decodedBytes = algorithm.Decode(encodedBytes);

                // Assert
                decodedBytes.Should().BeEquivalentTo(plainBytes);
            }

            [TestMethod]
            public void Encode_AppendixC1_EncodedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC1_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixC1_PlainText;
                var expectedEncodedBytes = Examples.AppendixC1_EncodedText;

                // Act
                var encodedBytes = algorithm.Encode(plainBytes);

                // Assert
                encodedBytes.Should().BeEquivalentTo(expectedEncodedBytes);
            }

            [TestMethod]
            public void Decode_AppendixC1_DecodedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC1_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var encodedBytes = Examples.AppendixC1_EncodedText;
                var expectedDecodedBytes = Examples.AppendixC1_PlainText;

                // Act
                var decodedBytes = algorithm.Decode(encodedBytes);

                // Assert
                decodedBytes.Should().BeEquivalentTo(expectedDecodedBytes);
            }

            [TestMethod]
            public void EncodeDecode_AppendixC1_EncodedDecodedMatch()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC1_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixC1_PlainText;

                // Act
                var encodedBytes = algorithm.Encode(plainBytes);
                var decodedBytes = algorithm.Decode(encodedBytes);

                // Assert
                decodedBytes.Should().BeEquivalentTo(plainBytes);
            }
        }

        [TestClass]
        public class AES192
        {
            [TestMethod]
            public void Encode_AppendixC2_EncodedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC2_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixC2_PlainText;
                var expectedEncodedBytes = Examples.AppendixC2_EncodedText;

                // Act
                var encodedBytes = algorithm.Encode(plainBytes);

                // Assert
                encodedBytes.Should().BeEquivalentTo(expectedEncodedBytes);
            }

            [TestMethod]
            public void Decode_AppendixC2_DecodedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC2_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var encodedBytes = Examples.AppendixC2_EncodedText;
                var expectedDecodedBytes = Examples.AppendixC2_PlainText;

                // Act
                var decodedBytes = algorithm.Decode(encodedBytes);

                // Assert
                decodedBytes.Should().BeEquivalentTo(expectedDecodedBytes);
            }

            [TestMethod]
            public void EncodeDecode_AppendixC2_EncodedDecodedMatch()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC2_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixC2_PlainText;

                // Act
                var encodedBytes = algorithm.Encode(plainBytes);
                var decodedBytes = algorithm.Decode(encodedBytes);

                // Assert
                decodedBytes.Should().BeEquivalentTo(plainBytes);
            }
        }

        [TestClass]
        public class AES256
        {
            [TestMethod]
            public void Encode_AppendixC3_EncodedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC3_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixC3_PlainText;
                var expectedEncodedBytes = Examples.AppendixC3_EncodedText;

                // Act
                var encodedBytes = algorithm.Encode(plainBytes);

                // Assert
                encodedBytes.Should().BeEquivalentTo(expectedEncodedBytes);
            }

            [TestMethod]
            public void Decode_AppendixC3_DecodedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC3_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var encodedBytes = Examples.AppendixC3_EncodedText;
                var expectedDecodedBytes = Examples.AppendixC3_PlainText;

                // Act
                var decodedBytes = algorithm.Decode(encodedBytes);

                // Assert
                decodedBytes.Should().BeEquivalentTo(expectedDecodedBytes);
            }

            [TestMethod]
            public void EncodeDecode_AppendixC3_EncodedDecodedMatch()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC3_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixC3_PlainText;

                // Act
                var encodedBytes = algorithm.Encode(plainBytes);
                var decodedBytes = algorithm.Decode(encodedBytes);

                // Assert
                decodedBytes.Should().BeEquivalentTo(plainBytes);
            }
        }
    }
}
