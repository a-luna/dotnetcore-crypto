using System;
using System.IO;
using System.Threading.Tasks;
using AaronLuna.Common.IO;

namespace AaronLuna.Crypto.Test
{
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class CryptoFilesTestFixture
    {
        const string InputFileName = "smallFile.jpg";
        string InputMoveFileName = $"{InputFileName}.original";
        string EncryptedFileName = $"{InputFileName}.encrypted";
        string InfoXmlFileName = $"{InputFileName}.encrypted.xml";
        string PublicKeyFileName = "publicKey.xml";
        string PrivateKeyFileName = "privateKey.xml";

        string _testFilesFolder;
        string _keysFolder;
        string _inputFilePath;
        string _inputMoveFilePath;
        string _encryptedFilePath;
        string _infoXmlFilePath;
        string _publicKeyFilePath;
        string _privateKeyFilePath;

        [TestInitialize]
        public void Setup()
        {
            var currentPath = Directory.GetCurrentDirectory();
            var index = currentPath.IndexOf("bin", StringComparison.Ordinal);

            _testFilesFolder = $"{currentPath.Remove(index - 1)}{Path.DirectorySeparatorChar}TestFiles{Path.DirectorySeparatorChar}CryptoFilesTestFixture{Path.DirectorySeparatorChar}";
            _keysFolder = _testFilesFolder + $"Keys{Path.DirectorySeparatorChar}";

            _inputFilePath = _testFilesFolder + InputFileName;
            _inputMoveFilePath = _testFilesFolder + InputMoveFileName;
            _encryptedFilePath = _testFilesFolder + EncryptedFileName;
            _infoXmlFilePath = _testFilesFolder + InfoXmlFileName;
            _publicKeyFilePath = _keysFolder + PublicKeyFileName;
            _privateKeyFilePath = _keysFolder + PrivateKeyFileName;

            FileHelper.DeleteFileIfAlreadyExists(_inputMoveFilePath);
            FileHelper.DeleteFileIfAlreadyExists(_encryptedFilePath);
            FileHelper.DeleteFileIfAlreadyExists(_infoXmlFilePath);
            FileHelper.DeleteFileIfAlreadyExists(_publicKeyFilePath);
            FileHelper.DeleteFileIfAlreadyExists(_privateKeyFilePath);
        }

        [TestMethod]
        public async Task VerifyEncryptAndDecryptFile_SHA2_256()
        {
            Assert.IsTrue(File.Exists(_inputFilePath));
            Assert.IsFalse(File.Exists(_encryptedFilePath));
            Assert.IsFalse(File.Exists(_infoXmlFilePath));
            Assert.IsFalse(File.Exists(_publicKeyFilePath));
            Assert.IsFalse(File.Exists(_privateKeyFilePath));

            CryptoKeys.CreateNewKeyPair(_keysFolder);

            Assert.IsTrue(File.Exists(_publicKeyFilePath));
            Assert.IsTrue(File.Exists(_privateKeyFilePath));

            var encryptResult = await CryptoFiles.EncryptFileAsync(_inputFilePath, _publicKeyFilePath);
            if (encryptResult.Failure)
            {
                Assert.Fail("Error occurred encrypting file.");
            }

            var infoXml = encryptResult.Value;

            File.Move(_inputFilePath, _inputMoveFilePath);

            Assert.IsFalse(File.Exists(_inputFilePath));
            Assert.IsTrue(File.Exists(_inputMoveFilePath));
            Assert.IsTrue(File.Exists(_encryptedFilePath));
            Assert.IsTrue(File.Exists(_infoXmlFilePath));

            var decryptResult = await CryptoFiles.DecryptFileAsync(_encryptedFilePath, infoXml, _privateKeyFilePath);
            if (decryptResult.Failure)
            {
                Assert.Fail("Error occurred decrypting file.");
            }

            Assert.IsTrue(File.Exists(_inputFilePath));
            Assert.IsTrue(decryptResult.Success);

            File.Delete(_publicKeyFilePath);
            File.Delete(_privateKeyFilePath);
            File.Delete(_infoXmlFilePath);
            File.Delete(_encryptedFilePath);
            File.Delete(_inputFilePath);
            File.Move(_inputMoveFilePath, _inputFilePath);
        }

        [TestMethod]
        public async Task VerifyEncryptAndDecryptFile_SHA2_384()
        {
            CryptoKeys.CreateNewKeyPair(_keysFolder);

            var encryptResult = await CryptoFiles.EncryptFileAsync(_inputFilePath, _publicKeyFilePath, HashAlgorithmType.SHA2_384);
            if (encryptResult.Failure)
            {
                Assert.Fail("Error occurred encrypting file.");
            }

            var infoXml = encryptResult.Value;
            Assert.IsTrue(infoXml.FileManifestHashAlgorithmType == HashAlgorithmType.SHA2_384);

            File.Move(_inputFilePath, _inputMoveFilePath);

            var decryptResult = await CryptoFiles.DecryptFileAsync(_encryptedFilePath, infoXml, _privateKeyFilePath);
            if (decryptResult.Failure)
            {
                Assert.Fail("Error occurred decrypting file.");
            }

            Assert.IsTrue(File.Exists(_inputFilePath));
            Assert.IsTrue(decryptResult.Success);

            File.Delete(_publicKeyFilePath);
            File.Delete(_privateKeyFilePath);
            File.Delete(_infoXmlFilePath);
            File.Delete(_encryptedFilePath);
            File.Delete(_inputFilePath);
            File.Move(_inputMoveFilePath, _inputFilePath);
        }

        [TestMethod]
        public async Task VerifyEncryptAndDecryptFile_SHA2_512()
        {
            CryptoKeys.CreateNewKeyPair(_keysFolder);

            var encryptResult = await CryptoFiles.EncryptFileAsync(_inputFilePath, _publicKeyFilePath, HashAlgorithmType.SHA2_512);
            if (encryptResult.Failure)
            {
                Assert.Fail("Error occurred encrypting file.");
            }

            var infoXml = encryptResult.Value;
            Assert.IsTrue(infoXml.FileManifestHashAlgorithmType == HashAlgorithmType.SHA2_512);

            File.Move(_inputFilePath, _inputMoveFilePath);

            var decryptResult = await CryptoFiles.DecryptFileAsync(_encryptedFilePath, infoXml, _privateKeyFilePath);
            if (decryptResult.Failure)
            {
                Assert.Fail("Error occurred decrypting file.");
            }

            Assert.IsTrue(File.Exists(_inputFilePath));
            Assert.IsTrue(decryptResult.Success);

            File.Delete(_publicKeyFilePath);
            File.Delete(_privateKeyFilePath);
            File.Delete(_infoXmlFilePath);
            File.Delete(_encryptedFilePath);
            File.Delete(_inputFilePath);
            File.Move(_inputMoveFilePath, _inputFilePath);
        }

        [TestMethod]
        public async Task VerifyEncryptAndDecryptFile_SHA3_256()
        {
            CryptoKeys.CreateNewKeyPair(_keysFolder);

            var encryptResult = await CryptoFiles.EncryptFileAsync(_inputFilePath, _publicKeyFilePath, HashAlgorithmType.SHA3_256);
            if (encryptResult.Failure)
            {
                Assert.Fail("Error occurred encrypting file.");
            }

            var infoXml = encryptResult.Value;
            Assert.IsTrue(infoXml.FileManifestHashAlgorithmType == HashAlgorithmType.SHA3_256);

            File.Move(_inputFilePath, _inputMoveFilePath);

            var decryptResult = await CryptoFiles.DecryptFileAsync(_encryptedFilePath, infoXml, _privateKeyFilePath);
            if (decryptResult.Failure)
            {
                Assert.Fail("Error occurred decrypting file.");
            }

            Assert.IsTrue(File.Exists(_inputFilePath));
            Assert.IsTrue(decryptResult.Success);

            File.Delete(_publicKeyFilePath);
            File.Delete(_privateKeyFilePath);
            File.Delete(_infoXmlFilePath);
            File.Delete(_encryptedFilePath);
            File.Delete(_inputFilePath);
            File.Move(_inputMoveFilePath, _inputFilePath);
        }

        [TestMethod]
        public async Task VerifyEncryptAndDecryptFile_SHA3_384()
        {
            CryptoKeys.CreateNewKeyPair(_keysFolder);

            var encryptResult = await CryptoFiles.EncryptFileAsync(_inputFilePath, _publicKeyFilePath, HashAlgorithmType.SHA3_384);
            if (encryptResult.Failure)
            {
                Assert.Fail("Error occurred encrypting file.");
            }

            var infoXml = encryptResult.Value;
            Assert.IsTrue(infoXml.FileManifestHashAlgorithmType == HashAlgorithmType.SHA3_384);

            File.Move(_inputFilePath, _inputMoveFilePath);

            var decryptResult = await CryptoFiles.DecryptFileAsync(_encryptedFilePath, infoXml, _privateKeyFilePath);
            if (decryptResult.Failure)
            {
                Assert.Fail("Error occurred decrypting file.");
            }

            Assert.IsTrue(File.Exists(_inputFilePath));
            Assert.IsTrue(decryptResult.Success);

            File.Delete(_publicKeyFilePath);
            File.Delete(_privateKeyFilePath);
            File.Delete(_infoXmlFilePath);
            File.Delete(_encryptedFilePath);
            File.Delete(_inputFilePath);
            File.Move(_inputMoveFilePath, _inputFilePath);
        }

        [TestMethod]
        public async Task VerifyEncryptAndDecryptFile_SHA3_512()
        {
            CryptoKeys.CreateNewKeyPair(_keysFolder);

            var encryptResult = await CryptoFiles.EncryptFileAsync(_inputFilePath, _publicKeyFilePath, HashAlgorithmType.SHA3_512);
            if (encryptResult.Failure)
            {
                Assert.Fail("Error occurred encrypting file.");
            }

            var infoXml = encryptResult.Value;
            Assert.IsTrue(infoXml.FileManifestHashAlgorithmType == HashAlgorithmType.SHA3_512);

            File.Move(_inputFilePath, _inputMoveFilePath);

            var decryptResult = await CryptoFiles.DecryptFileAsync(_encryptedFilePath, infoXml, _privateKeyFilePath);
            if (decryptResult.Failure)
            {
                Assert.Fail("Error occurred decrypting file.");
            }

            Assert.IsTrue(File.Exists(_inputFilePath));
            Assert.IsTrue(decryptResult.Success);

            File.Delete(_publicKeyFilePath);
            File.Delete(_privateKeyFilePath);
            File.Delete(_infoXmlFilePath);
            File.Delete(_encryptedFilePath);
            File.Delete(_inputFilePath);
            File.Move(_inputMoveFilePath, _inputFilePath);
        }
    }
}
