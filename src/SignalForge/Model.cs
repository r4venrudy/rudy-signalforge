namespace SignalForge;

public sealed record SecurityEvent(DateTimeOffset Time, string Source, string Id,
                                   IReadOnlyDictionary<string, string> Fields)
{
    public string? Get(string name) => name == "source" ? Source :
        Fields.TryGetValue(name, out string? value) ? value : null;
}

public sealed record Evidence(DateTimeOffset Time, string Source, string Id);

public sealed record Alert(string Rule, string Severity, string[] Group,
                           DateTimeOffset Time, Evidence[] Evidence);
