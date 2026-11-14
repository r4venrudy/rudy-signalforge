using SignalForge;
using System.Text.Json;

var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
try
{
    if (args is ["--version"])
    {
        Console.WriteLine("0.1.0-preview");
        return 0;
    }
    if (args is ["--help"])
    {
        Console.WriteLine("signalforge lint RULES\nsignalforge replay RULES EVENTS\nsignalforge test RULES EVENTS EXPECTED");
        return 0;
    }
    if (args.Length < 2 || !((args[0] == "lint" && args.Length == 2) ||
                            (args[0] == "replay" && args.Length == 3) ||
                            (args[0] == "test" && args.Length == 4)))
        throw new FormatException("invalid command or arguments. See --help.");
    IReadOnlyList<Rule> rules = Rules.Load(args[1]);
    if (args[0] == "lint")
    {
        Console.WriteLine(JsonSerializer.Serialize(new { rules = rules.Select(rule => rule.Id) }, options));
        return 0;
    }
    using FileStream stream = File.OpenRead(args[2]);
    var alerts = new ReplayEngine().Run(rules, Inputs.ReadEvents(stream));
    if (args[0] == "test")
    {
        var result = Expectations.Verify(args[3], alerts);
        Console.WriteLine(JsonSerializer.Serialize(result, options));
        return result.Passed ? 0 : 3;
    }
    Console.WriteLine(JsonSerializer.Serialize(new { schemaVersion = 1, alerts }, options));
    return 0;
}
catch (Exception error) when (error is IOException or FormatException or JsonException or
                                    ArgumentException or InvalidOperationException or UnauthorizedAccessException)
{
    // Invalid JSON can include input excerpts. Keep raw telemetry out of diagnostics.
    string message = error is JsonException or InvalidOperationException
        ? "invalid JSON or JSON field" : error.Message;
    Console.Error.WriteLine($"signalforge: {message}");
    return 2;
}
