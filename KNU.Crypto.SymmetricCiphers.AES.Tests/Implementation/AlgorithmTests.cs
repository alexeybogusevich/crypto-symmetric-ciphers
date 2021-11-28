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
            public void Encode_AppendixB_EncryptedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixB_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixB_PlainText;
                var expectedEncryptedBytes = Examples.AppendixB_EncryptedText;

                // Act
                var encryptedBytes = algorithm.Encrypt(plainBytes);

                // Assert
                encryptedBytes.Should().BeEquivalentTo(expectedEncryptedBytes);
            }

            [TestMethod]
            public void Decode_AppendixB_DecryptedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixB_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var encryptedBytes = Examples.AppendixB_EncryptedText;
                var expectedDecryptedBytes = Examples.AppendixB_PlainText;

                // Act
                var decryptedBytes = algorithm.Decrypt(encryptedBytes);

                // Assert
                decryptedBytes.Should().BeEquivalentTo(expectedDecryptedBytes);
            }

            [TestMethod]
            public void EncodeDecode_AppendixB_EncryptedDecryptedMatch()
            {
                // Arrange
                var cipherBytes = Examples.AppendixB_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixB_PlainText;

                // Act
                var encryptedBytes = algorithm.Encrypt(plainBytes);
                var decryptedBytes = algorithm.Decrypt(encryptedBytes);

                // Assert
                decryptedBytes.Should().BeEquivalentTo(plainBytes);
            }

            [TestMethod]
            public void Encode_AppendixC1_EncryptedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC1_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixC1_PlainText;
                var expectedEncryptedBytes = Examples.AppendixC1_EncryptedText;

                // Act
                var encryptedBytes = algorithm.Encrypt(plainBytes);

                // Assert
                encryptedBytes.Should().BeEquivalentTo(expectedEncryptedBytes);
            }

            [TestMethod]
            public void Decode_AppendixC1_DecryptedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC1_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var encryptedBytes = Examples.AppendixC1_EncryptedText;
                var expectedDecryptedBytes = Examples.AppendixC1_PlainText;

                // Act
                var decryptedBytes = algorithm.Decrypt(encryptedBytes);

                // Assert
                decryptedBytes.Should().BeEquivalentTo(expectedDecryptedBytes);
            }

            [TestMethod]
            public void EncodeDecode_AppendixC1_EncryptedDecryptedMatch()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC1_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixC1_PlainText;

                // Act
                var encryptedBytes = algorithm.Encrypt(plainBytes);
                var decryptedBytes = algorithm.Decrypt(encryptedBytes);

                // Assert
                decryptedBytes.Should().BeEquivalentTo(plainBytes);
            }
        }

        [TestClass]
        public class AES192
        {
            [TestMethod]
            public void Encode_AppendixC2_EncryptedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC2_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixC2_PlainText;
                var expectedEncryptedBytes = Examples.AppendixC2_EncryptedText;

                // Act
                var encryptedBytes = algorithm.Encrypt(plainBytes);

                // Assert
                encryptedBytes.Should().BeEquivalentTo(expectedEncryptedBytes);
            }

            [TestMethod]
            public void Decode_AppendixC2_DecryptedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC2_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var encryptedBytes = Examples.AppendixC2_EncryptedText;
                var expectedDecryptedBytes = Examples.AppendixC2_PlainText;

                // Act
                var decryptedBytes = algorithm.Decrypt(encryptedBytes);

                // Assert
                decryptedBytes.Should().BeEquivalentTo(expectedDecryptedBytes);
            }

            [TestMethod]
            public void EncodeDecode_AppendixC2_EncryptedDecryptedMatch()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC2_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixC2_PlainText;

                // Act
                var encryptedBytes = algorithm.Encrypt(plainBytes);
                var decryptedBytes = algorithm.Decrypt(encryptedBytes);

                // Assert
                decryptedBytes.Should().BeEquivalentTo(plainBytes);
            }
        }

        [TestClass]
        public class AES256
        {
            [TestMethod]
            public void Encode_AppendixC3_EncryptedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC3_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixC3_PlainText;
                var expectedEncryptedBytes = Examples.AppendixC3_EncryptedText;

                // Act
                var encryptedBytes = algorithm.Encrypt(plainBytes);

                // Assert
                encryptedBytes.Should().BeEquivalentTo(expectedEncryptedBytes);
            }

            [TestMethod]
            public void Decode_AppendixC3_DecryptedCorrectly()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC3_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var encryptedBytes = Examples.AppendixC3_EncryptedText;
                var expectedDecryptedBytes = Examples.AppendixC3_PlainText;

                // Act
                var decryptedBytes = algorithm.Decrypt(encryptedBytes);

                // Assert
                decryptedBytes.Should().BeEquivalentTo(expectedDecryptedBytes);
            }

            [TestMethod]
            public void EncodeDecode_AppendixC3_EncryptedDecryptedMatch()
            {
                // Arrange
                var cipherBytes = Examples.AppendixC3_CipherKey;
                var algorithm = new Algorithm(cipherBytes);

                var plainBytes = Examples.AppendixC3_PlainText;

                // Act
                var encryptedBytes = algorithm.Encrypt(plainBytes);
                var decryptedBytes = algorithm.Decrypt(encryptedBytes);

                // Assert
                decryptedBytes.Should().BeEquivalentTo(plainBytes);
            }
        }
    }
}
