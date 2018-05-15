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
        const string InputFileName = "Usage.pdf";
        const string EncryptedFileName = "Usage.pdf.encrypted";
        const string InfoXmlFileName = "Usage.pdf.encrypted.xml";
        const string PublicKeyFileName = "publicKey.xml";
        const string PrivateKeyFileName = "privateKey.xml";

        string _testFilesFolder;
        string _keysFolder;
        string _inputFilePath;
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
            _encryptedFilePath = _testFilesFolder + EncryptedFileName;
            _infoXmlFilePath = _testFilesFolder + InfoXmlFileName;
            _publicKeyFilePath = _keysFolder + PublicKeyFileName;
            _privateKeyFilePath = _keysFolder + PrivateKeyFileName;

            FileHelper.DeleteFileIfAlreadyExists(_encryptedFilePath);
            FileHelper.DeleteFileIfAlreadyExists(_infoXmlFilePath);
            FileHelper.DeleteFileIfAlreadyExists(_publicKeyFilePath);
            FileHelper.DeleteFileIfAlreadyExists(_privateKeyFilePath);
        }

        [TestMethod]
        public async Task VerifyEncryptAndDecryptFile()
        {
            Assert.IsTrue(File.Exists(_inputFilePath));
            Assert.IsFalse(File.Exists(_encryptedFilePath));
            Assert.IsFalse(File.Exists(_infoXmlFilePath));
            Assert.IsFalse(File.Exists(_publicKeyFilePath));
            Assert.IsFalse(File.Exists(_privateKeyFilePath));

            CryptoKeys.CreateNewKeyPair(_keysFolder);

            Assert.IsTrue(File.Exists(_publicKeyFilePath));
            Assert.IsTrue(File.Exists(_privateKeyFilePath));

            await CryptoFiles.EncryptFileAsync(_inputFilePath, _publicKeyFilePath);

            Assert.IsTrue(File.Exists(_inputFilePath));
            Assert.IsTrue(File.Exists(_encryptedFilePath));
            Assert.IsTrue(File.Exists(_infoXmlFilePath));

            var decryptResult = await CryptoFiles.DecryptFileAsync(_infoXmlFilePath, _privateKeyFilePath);

            Assert.IsTrue(decryptResult.Success);
        }
    }
}
