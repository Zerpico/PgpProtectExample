using PgpProtection;

namespace PgpAppExample;

class Program
{
    static void Main(string[] args)
    {
        //путь до наших сгенерированных ключей
        string publicKeyFilePath = @"public_key.asc";
        string privateKeyFilePath = @"private_key.asc";
        string secretKey = "MySuperP@ss0wrdKey";

        var licManager = new LicenseManager(publicKeyFilePath, privateKeyFilePath);

        Dictionary<int, int> licenseData = new()
        {
            { 1, 100 }, // Feature ID 1, Value 100
            { 2, 50  }, // Feature ID 2, Value 50
            { 3, 1   }  // Feature ID 3, Value 1
        };

        // Генерация лицензионного ключа
        string licenseKey = licManager.GenerateLicenseKey(licenseData);
        Console.WriteLine($"Лицензионный ключ: {licenseKey}" + Environment.NewLine);

        // Проверка лицензионного ключа
        Dictionary<int, int> verifiedData = licManager.VerifyLicenseKey(licenseKey, secretKey);

        if (verifiedData != null)
        {
            Console.WriteLine("Лицензионный ключ действителен. Данные:");
            foreach (var kvp in verifiedData)
                Console.WriteLine($"Feature ID: {kvp.Key}, Value: {kvp.Value}");

        }
        else
        {
            Console.WriteLine("Лицензионный ключ недействителен.");
        }
    }
}
