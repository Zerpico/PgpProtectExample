# PgpProtectExample
Пример простого шифрования/дешифрования с помощью PGP

В LicenseManager описаны 2 метода:
 - __GenerateLicenseKey__ - для генерации лицензионого (необходим публичный ключ)
 - __VerifyLicenseKey__ - для дешифровки лицензионого ключа (необходим приватный ключ и секрет)

Перед использованием обязательно необходимо сгенернировать публичный и приватный ключи. Можно сделать 2 способами:

### С помощью библиотеки BouncyCastle

```csharp
public static void GenerateKeyFiles(string publicKeyPath, string privateKeyPath, string userId, string password)
{  
    // Конфигурация алгоритмов и параметров
    const int KeyStrength = 2048; // Максимальная длина ключа
    var random = new SecureRandom();
    var keyPairGenerator = new RsaKeyPairGenerator();

    // Настройка параметров генерации ключей
    keyPairGenerator.Init(new KeyGenerationParameters(random, KeyStrength));
    // Генерация пары ключей (приватный и публичный)
    AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();    
    PgpKeyPair pgpKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, keyPair, DateTime.UtcNow);
    // Создание секретного ключа
    PgpSecretKey secretKey = new PgpSecretKey(
        PgpSignature.DefaultCertification,
        pgpKeyPair,
        userId,
        SymmetricKeyAlgorithmTag.Aes256, // Используйте AES256 для сильного шифрования секретного ключа
        password.ToCharArray(), // Пароль для защиты приватного ключа
        true,       // useSha1 (использовать SHA1 для проверки контрольной суммы)
        null,       // hashedPackets (можно оставить null)
        null,       // unhashedPackets (можно оставить null)
        random
    );
    // Экспорт ключей в файлы
    ExportKeyPair(publicKeyPath, privateKeyPath, secretKey);
}

private static void ExportKeyPair(string pubKeyPath, string secKeyPath, PgpSecretKey secretKey)
{
    using (Stream pubOut = File.Create(pubKeyPath))
    using (ArmoredOutputStream armoredPubKeyOut = new ArmoredOutputStream(pubOut))
    using (MemoryStream pubRingStream = new MemoryStream()) 
    using (Stream secOut = File.Create(secKeyPath))
    using (ArmoredOutputStream armoredSecKeyOut = new ArmoredOutputStream(secOut))
    {
        // 8. Кодирование ключей в формате ASCII Armor
        PgpPublicKeyRing pubRing = new PgpPublicKeyRing(secretKey.PublicKey.GetEncoded());
        pubRing.Encode(armoredPubKeyOut);
        PgpSecretKeyRing secRing = new PgpSecretKeyRing(secretKey.GetEncoded());
        secRing.Encode(armoredSecKeyOut);
        armoredPubKeyOut.Flush();
        armoredSecKeyOut.Flush();
    }
}

GenerateKeyFiles("public_key.asc", "private_key.asc", "info@mycompany.com", "MySuperP@ssw0rd");
```

### С помощью утилиты gpg

```bash
gpg --full-generate-key
gpg --armor --export user@yourdomain.com > public_key.asc
gpg --armor --export-secret-key user@yourdomain.com >  private_key.asc
```
При генерации ключа следует выбрать метод шифрования (RSA and RSA) или (ECC (sign and encrypt)). Чтобы ключом можно было дешифровать, иначе будет только подпись сертификатом
