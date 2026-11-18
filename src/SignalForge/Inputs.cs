using System.Buffers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SignalForge;

public static partial class Inputs
{
    internal const int MaxEvents = 250_000;
    private const int MaxLine = 32 * 1024;
    private const int MaxRuleFile = 512 * 1024;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    [GeneratedRegex(@"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\z", RegexOptions.CultureInvariant)]
    internal static partial Regex Identifier();

    internal static JsonDocument Parse(ReadOnlyMemory<byte> data) =>
        JsonDocument.Parse(data, new JsonDocumentOptions { MaxDepth = 8, AllowDuplicateProperties = false });

    private static ReadOnlyMemory<byte> StripUtf8Signature(ReadOnlyMemory<byte> data) =>
        data.Span.StartsWith("\uFEFF"u8) ? data[3..] : data;

    internal static JsonDocument OpenRuleFile(string path)
    {
        using FileStream file = File.OpenRead(path);
        if (file.Length > MaxRuleFile)
            throw new FormatException("rule file exceeds 512 KiB");
        byte[] bytes = new byte[checked((int)file.Length)];
        file.ReadExactly(bytes);
        if (file.ReadByte() != -1)
            throw new FormatException("rule file grew while reading");
        return Parse(StripUtf8Signature(bytes));
    }

    internal static void Object(JsonElement value, params string[] allowed)
    {
        if (value.ValueKind != JsonValueKind.Object)
            throw new FormatException("expected an object");
        foreach (JsonProperty property in value.EnumerateObject())
            if (!allowed.Contains(property.Name, StringComparer.Ordinal))
                throw new FormatException("unexpected object property");
    }

    internal static JsonElement Required(JsonElement value, string name) =>
        value.TryGetProperty(name, out JsonElement item) ? item :
        throw new FormatException($"missing property {name}");

    internal static string Text(JsonElement value, int max = 256)
    {
        if (value.ValueKind != JsonValueKind.String)
            throw new FormatException("expected string");
        string text = value.GetString()!;
        if (text.Length == 0 || text.Length > max || text.Any(char.IsControl))
            throw new FormatException("invalid string length or control character");
        return text;
    }

    internal static string Key(JsonElement value)
    {
        string text = Text(value, 64);
        return Identifier().IsMatch(text) ? text : throw new FormatException("invalid identifier");
    }

    internal static int Integer(JsonElement value, int min, int max)
    {
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out int number) ||
            number < min || number > max)
            throw new FormatException($"expected integer in range {min} through {max}");
        return number;
    }

    public static IEnumerable<SecurityEvent> ReadEvents(Stream stream)
    {
        var line = new ArrayBufferWriter<byte>();
        byte[] page = new byte[8192];
        int number = 0;
        var ids = new HashSet<(string, string)>();
        DateTimeOffset? previous = null;
        int read;
        while ((read = stream.Read(page)) > 0)
        {
            int start = 0;
            while (start < read)
            {
                int newline = Array.IndexOf(page, (byte)'\n', start, read - start);
                int end = newline < 0 ? read : newline;
                if (line.WrittenCount + end - start > MaxLine)
                    throw new FormatException($"event line {number + 1} exceeds 32 KiB");
                line.Write(page.AsSpan(start, end - start));
                if (newline < 0)
                    break;
                yield return Finish();
                start = newline + 1;
            }
        }
        if (line.WrittenCount > 0)
            yield return Finish();

        SecurityEvent Finish()
        {
            if (++number > MaxEvents)
                throw new FormatException("event limit exceeded");
            SecurityEvent item;
            try
            {
                ReadOnlyMemory<byte> bytes = line.WrittenMemory;
                item = Decode(number == 1 ? StripUtf8Signature(bytes) : bytes);
            }
            catch (Exception error) when (error is JsonException or FormatException or
                                                InvalidOperationException or DecoderFallbackException)
            {
                throw new FormatException($"invalid event at line {number}", error);
            }
            if (previous > item.Time)
                throw new FormatException($"event timestamps are out of order at line {number}");
            if (!ids.Add((item.Source, item.Id)))
                throw new FormatException($"duplicate source and event ID at line {number}");
            previous = item.Time;
            line.Clear();
            return item;
        }
    }

    [GeneratedRegex(@"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)\z", RegexOptions.CultureInvariant)]
    private static partial Regex Timestamp();

    private static SecurityEvent Decode(ReadOnlyMemory<byte> data)
    {
        _ = Utf8.GetCharCount(data.Span);
        using JsonDocument document = Parse(data);
        JsonElement root = document.RootElement;
        Object(root, "ts", "source", "id", "fields");
        string time = Text(Required(root, "ts"), 40);
        if (!Timestamp().IsMatch(time) ||
            !DateTimeOffset.TryParse(time, System.Globalization.CultureInfo.InvariantCulture,
                                     System.Globalization.DateTimeStyles.None, out DateTimeOffset timestamp))
            throw new FormatException("expected ISO 8601 timestamp with offset");
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        JsonElement body = Required(root, "fields");
        if (body.ValueKind != JsonValueKind.Object)
            throw new FormatException("expected fields object");
        foreach (JsonProperty property in body.EnumerateObject())
        {
            if (fields.Count == 32 || property.Name == "source" || !Identifier().IsMatch(property.Name))
                throw new FormatException("invalid event field");
            fields.Add(property.Name, Text(property.Value));
        }
        return new(timestamp.ToUniversalTime(), Key(Required(root, "source")), Key(Required(root, "id")), fields);
    }
}
