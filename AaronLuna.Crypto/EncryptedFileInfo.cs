namespace AaronLuna.Crypto
{
    using System;
    using System.IO;
    using System.Security.Authentication;
    using System.Xml.Serialization;

    using Common.Result;

    public class EncryptedFileInfo
    {
        public string FileName { get; set; }
        public string EncryptedFileName { get; set; }
        public CipherAlgorithmType FileEncryptionAlgorithmType { get; set; }
        public string EncryptedAesKey { get; set; }
        public string EncryptedAesIv { get; set; }
        public string FileManifestHashAlgorithmType { get; set; }
        public string EncryptedFileManifest { get; set; }
        public ExchangeAlgorithmType FileManifestKeyEncryptionAlgorithmType { get; set; }
        public string EncryptedFileManifestKey { get; set; }

        public static void Serialize(EncryptedFileInfo fileInfo, string filePath)
        {
            var serializer = new XmlSerializer(typeof(EncryptedFileInfo));
            using (var writer = new StreamWriter(filePath))
            {
                serializer.Serialize(writer, fileInfo);
            }
        }

        public static Result<EncryptedFileInfo> Deserialize(string filePath)
        {
            EncryptedFileInfo fileInfo;
            try
            {
                var deserializer = new XmlSerializer(typeof(EncryptedFileInfo));
                using (var reader = new StreamReader(filePath))
                {
                    fileInfo = (EncryptedFileInfo)deserializer.Deserialize(reader);
                }
            }
            catch (Exception ex)
            {
                return Result.Fail<EncryptedFileInfo>($"{ex.Message} ({ex.GetType()})");
            }
            
            return Result.Ok(fileInfo);
        }
    }
}
