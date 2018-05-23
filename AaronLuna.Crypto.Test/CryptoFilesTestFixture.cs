namespace AaronLuna.Crypto.Test
{
    using System;
    using System.IO;
    using System.Threading.Tasks;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

    using Common.IO;

    [TestClass]
    public class CryptoFilesTestFixture
    {
        const string InputFileName = "smallFile.jpg";
        const string PublicKeyFileName = "publicKey.xml";
        const string PrivateKeyFileName = "privateKey.xml";

        readonly string _inputMoveFileName = $"{InputFileName}.original";
        readonly string _encryptedFileName = $"{InputFileName}.encrypted";
        readonly string _encryptedFileInfoXmlFileName = $"{InputFileName}.encrypted.xml";

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
            _inputMoveFilePath = _testFilesFolder + _inputMoveFileName;
            _encryptedFilePath = _testFilesFolder + _encryptedFileName;
            _infoXmlFilePath = _testFilesFolder + _encryptedFileInfoXmlFileName;
            _publicKeyFilePath = _keysFolder + PublicKeyFileName;
            _privateKeyFilePath = _keysFolder + PrivateKeyFileName;

            FileHelper.DeleteFileIfAlreadyExists(_inputMoveFilePath);
            FileHelper.DeleteFileIfAlreadyExists(_encryptedFilePath);
            FileHelper.DeleteFileIfAlreadyExists(_infoXmlFilePath);
            FileHelper.DeleteFileIfAlreadyExists(_publicKeyFilePath);
            FileHelper.DeleteFileIfAlreadyExists(_privateKeyFilePath);
        }

        [DataRow(HashAlgorithmType.HMAC_MD5, 128)]
        [DataRow(HashAlgorithmType.HMAC_SHA1, 160)]
        [DataRow(HashAlgorithmType.HMAC_SHA256, 256)]
        [DataRow(HashAlgorithmType.HMAC_SHA384, 384)]
        [DataRow(HashAlgorithmType.HMAC_SHA512, 512)]
        [DataRow(HashAlgorithmType.SHA2_256, 256)]
        [DataRow(HashAlgorithmType.SHA2_384, 384)]
        [DataRow(HashAlgorithmType.SHA2_512, 512)]
        [DataRow(HashAlgorithmType.SHA3_256, 256)]
        [DataRow(HashAlgorithmType.SHA3_384, 384)]
        [DataRow(HashAlgorithmType.SHA3_512, 512)]
        [DataTestMethod]
        public async Task VerifyFileEncryption(HashAlgorithmType hashAlgorithm, int bitCount)
        {
            Assert.IsTrue(File.Exists(_inputFilePath));
            Assert.IsFalse(File.Exists(_encryptedFilePath));
            Assert.IsFalse(File.Exists(_infoXmlFilePath));
            Assert.IsFalse(File.Exists(_publicKeyFilePath));
            Assert.IsFalse(File.Exists(_privateKeyFilePath));

            CryptoKeys.CreateNewKeyPair(_keysFolder);

            Assert.IsTrue(File.Exists(_publicKeyFilePath));
            Assert.IsTrue(File.Exists(_privateKeyFilePath));

            var encryptResult = await CryptoFiles.EncryptFileAsync(_inputFilePath, _publicKeyFilePath, hashAlgorithm);
            if (encryptResult.Failure)
            {
                Assert.Fail("Error occurred encrypting file.");
            }

            var encryptedFileInfo = encryptResult.Value;
            var encryptedFileHashBytes = Convert.FromBase64String(encryptedFileInfo.EncryptedFileDigest);

            Assert.IsTrue(encryptedFileHashBytes.Length * 8 == bitCount);
            Assert.IsTrue(encryptedFileInfo.FileDigestHashAlgorithmType == hashAlgorithm);

            File.Move(_inputFilePath, _inputMoveFilePath);

            Assert.IsFalse(File.Exists(_inputFilePath));
            Assert.IsTrue(File.Exists(_inputMoveFilePath));
            Assert.IsTrue(File.Exists(_encryptedFilePath));
            Assert.IsTrue(File.Exists(_infoXmlFilePath));

            var decryptResult = await CryptoFiles.DecryptFileAsync(_encryptedFilePath, _privateKeyFilePath, _infoXmlFilePath);
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
