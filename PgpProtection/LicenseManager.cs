using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace PgpProtection;

public class LicenseManager
{
    private readonly byte[] _publicKeyData;
    private readonly byte[] _privateKeyData;

    public LicenseManager(string publicKeyPath, string privateKeyPath)
    {
        using (var fileStream = File.Open(publicKeyPath, FileMode.Open, FileAccess.Read) ?? throw new FileLoadException("Failed load file", publicKeyPath))
        {
            _publicKeyData = new byte[fileStream.Length];
            StreamUtils.ReadStream(fileStream, out _publicKeyData);
        }

        using (var fileStream = File.Open(privateKeyPath, FileMode.Open, FileAccess.Read) ?? throw new FileLoadException("Failed load file", privateKeyPath))
        {
            _privateKeyData = new byte[fileStream.Length];
            StreamUtils.ReadStream(fileStream, out _privateKeyData);
        }
    }

    public LicenseManager(Stream publicKeyData, Stream privateKeyData)
    {
        _publicKeyData = new byte[publicKeyData.Length];
        StreamUtils.ReadStream(publicKeyData, out _publicKeyData);

        _privateKeyData = new byte[privateKeyData.Length];
        StreamUtils.ReadStream(privateKeyData, out _privateKeyData);
    }

    // <summary> Метод для генерации лицензионного ключа </summary>
    public string GenerateLicenseKey(Dictionary<int, int> data)
    {
        // Сериализация словаря в строку
        string serializedData = SerializeDictionary(data);
        // Шифрование хэша с использованием PGP и приватного ключа
        string hash = GenerateSHA256Hash(serializedData);

        // Складываем данные и хэш, затем кодируем с помощью PGP публичного ключа
        using var licenseData = new MemoryStream(System.Text.Encoding.Default.GetBytes(serializedData + "|" + hash));
        var encryptedLicense = EncryptData(licenseData);

        return Convert.ToBase64String(encryptedLicense);
    }

    /// <summary> Метод для проверки лицензионного ключа </summary>
    public Dictionary<int, int> VerifyLicenseKey(string licenseKey, string passPhrase)
    {
        // Расшифровка лицензионного ключа с использованием PGP приватного ключа
        using MemoryStream inputStream = new MemoryStream(Convert.FromBase64String(licenseKey));
        var decrypted = DecryptPgpData(inputStream, passPhrase);
        var decryptedStr = System.Text.Encoding.UTF8.GetString(decrypted);

        // отделяем данные от хэша через знак |
        string[] parts = decryptedStr.Split('|');
        if (parts.Length != 2)
            throw new ArgumentException("Invalid license key format");

        string decryptedData = parts[0];
        string decryptedHash = parts[1];

        var data = DeserializeDictionary(decryptedData) ?? throw new ArgumentException("Invalid license key");

        // Повторная сериализация словаря и генерация хэша для проверки
        string reSerializedData = SerializeDictionary(data);
        string reGeneratedHash = GenerateSHA256Hash(reSerializedData);

        // Сравнение хэшей.  Если они не совпадают, значит лицензия недействительна
        if (reGeneratedHash != decryptedHash)
            throw new ArgumentException("Хэши не совпадают. Недействительная лицензия.");

        return data;
    }

    /// <summary> Метод для сериализации словаря в строку </summary>
    private string SerializeDictionary(Dictionary<int, int> data)
    {
        return string.Join(";", data.Select(kv => $"{kv.Key}:{kv.Value}"));
    }

    /// <summary> Метод для десериализации словаря из строки </summary>
    private static Dictionary<int, int>? DeserializeDictionary(string serializedData)
    {
        try
        {
            return serializedData.Split(';')
                .Select(s => s.Split(':'))
                .ToDictionary(parts => int.Parse(parts[0]), parts => int.Parse(parts[1]));
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary> Шифрования данных с использованием PGP </summary>
    /// <param name="inputData">исходные данные</param>
    /// <returns>Зашифрованные данные</returns>
    private byte[] EncryptData(Stream inputData)
    {
        using Stream publicKeyStream = new MemoryStream(_publicKeyData);
        var publicKey = ReadPublicKey(publicKeyStream);

        if (publicKey == null || !publicKey.IsEncryptionKey)
        {
            throw new Exception("This public key is not intended for encryption!");
        }

        using MemoryStream bOut = new MemoryStream();
        using MemoryStream outputBytes = new MemoryStream();
        PgpCompressedDataGenerator dataCompressor = new PgpCompressedDataGenerator(CompressionAlgorithmTag.ZLib);
        PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();

        using (var pOut = lData.Open(dataCompressor.Open(outputBytes), PgpLiteralData.Binary, "license.dat", inputData.Length, DateTime.UtcNow))
        {
            Streams.CopyTo(inputData, pOut, Streams.DefaultBufferSize);
        }
#pragma warning disable CS0618 // member is obsolete
        dataCompressor.Close();
#pragma warning restore CS0618

        PgpEncryptedDataGenerator dataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, true, new SecureRandom());

        dataGenerator.AddMethod(publicKey);
        byte[] dataBytes = outputBytes.ToArray();
        byte[] result;
        using (var outputStream = new MemoryStream())
        {
            StreamUtils.WriteStream(dataGenerator.Open(outputStream, dataBytes.Length), ref dataBytes);
            result = outputStream.ToArray();
        }

        return result;
    }

    /// <summary> Расшифровки данных с использованием PGP </summary>
    /// <param name="inputStream">зашифрованные данные</param>
    /// <param name="passPhrase">ключ-пароль</param>
    /// <returns>Расшифрованные данные</returns>
    private byte[] DecryptPgpData(Stream inputStream, string passPhrase)
    {
        PgpObjectFactory pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
        PgpObject? pgp = pgpFactory?.NextPgpObject();

        if (pgp == null)
        {
            throw new PgpException("The PGP Object is null");
        }

        // the first object might be a PGP marker packet.
        PgpEncryptedDataList encryptedData;
        if (pgp is PgpEncryptedDataList list)
        {
            encryptedData = list;
        }
        else
        {
            encryptedData = (PgpEncryptedDataList)pgpFactory.NextPgpObject();
        }

        if (encryptedData == null)
        {
            throw new PgpException("The PGP Encrypted Data is null");
        }

        // find secret key
        using Stream privateKeyStream = new MemoryStream(_privateKeyData);
        PgpSecretKeyRingBundle pgpKeyRing = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
        // decrypt
        PgpPrivateKey? privateKey = null;
        PgpPublicKeyEncryptedData? pubKeyData = null;

        foreach (PgpPublicKeyEncryptedData pubKeyDataItem in encryptedData.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>())
        {
            privateKey = FindSecretKey(pgpKeyRing, pubKeyDataItem.KeyId, passPhrase.ToCharArray());

            if (privateKey != null)
            {
                pubKeyData = pubKeyDataItem;
                break;
            }
        }

        if (privateKey == null)
            throw new ArgumentException("Secret key for message not found.");

        if (pubKeyData == null)
            throw new ArgumentException("EncryptedData is not valid for current private key");


        PgpObjectFactory plainFact;
        using (Stream clear = pubKeyData.GetDataStream(privateKey))
        {
            plainFact = new PgpObjectFactory(clear);
        }

        PgpObject message = plainFact.NextPgpObject();

        if (message is PgpCompressedData compressedData)
        {
            using Stream compDataIn = compressedData.GetDataStream();
            PgpObjectFactory pgpCompressedFactory = new PgpObjectFactory(compDataIn);

            message = pgpCompressedFactory.NextPgpObject();
            if (message is PgpOnePassSignatureList)
            {
                message = pgpCompressedFactory.NextPgpObject();
            }

            PgpLiteralData literalData = (PgpLiteralData)message;
            using Stream unc = literalData.GetInputStream();

            using var reader = new BinaryReader(unc);
            return StreamUtils.ReadAllBytes(reader);
        }
        else if (message is PgpLiteralData literalData)
        {
            using Stream unc = literalData.GetInputStream();
            using var reader = new BinaryReader(unc);
            return StreamUtils.ReadAllBytes(reader);
        }
        else if (message is PgpOnePassSignatureList)
        {
            throw new PgpException("Encrypted message contains a signed message - not literal data.");
        }
        else
        {
            throw new PgpException("Message is not a simple encrypted file - type unknown.");
        }
    }

    private static PgpPrivateKey? FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
    {
        PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);
        if (pgpSecKey == null)
        {
            return null;
        }

        return pgpSecKey.ExtractPrivateKey(pass);
    }

    private static PgpPublicKey? ReadPublicKey(Stream inputStream)
    {
        inputStream = PgpUtilities.GetDecoderStream(inputStream);
        PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

        return pgpPub.GetKeyRings().SelectMany(x => x.GetPublicKeys())
            .FirstOrDefault(x => x.IsEncryptionKey);
    }

    // Метод для генерации SHA256 хэша
    private string GenerateSHA256Hash(string input)
    {
        using System.Security.Cryptography.SHA256 sha256 = System.Security.Cryptography.SHA256.Create();
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(input);
        byte[] hashBytes = sha256.ComputeHash(bytes);
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    }
}