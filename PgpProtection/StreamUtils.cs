
namespace PgpProtection;

public static class StreamUtils
{
    public static string GetString(Stream inputStream)
    {
        string output;
        using (StreamReader reader = new StreamReader(inputStream))
        {
            output = reader.ReadToEnd();
        }
        return output;
    }

    public static void WriteStream(Stream inputStream, ref byte[] dataBytes)
    {
        using Stream outputStream = inputStream;
        outputStream.Write(dataBytes, 0, dataBytes.Length);
    }

    public static void ReadStream(Stream inputStream, out byte[] outputBytes)
    {
        outputBytes = new byte[inputStream.Length];
        using Stream outputStream = inputStream;
        outputStream.Read(outputBytes, 0, outputBytes.Length);
    }

    public static byte[] ReadAllBytes(this BinaryReader reader)
    {
        const int bufferSize = 4096;
        using var ms = new MemoryStream();
        byte[] buffer = new byte[bufferSize];
        int count;

        while ((count = reader.Read(buffer, 0, buffer.Length)) != 0)
        {
            ms.Write(buffer, 0, count);
        }
        return ms.ToArray();
    }
}