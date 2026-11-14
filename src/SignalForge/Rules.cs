using System.Text.Json;

namespace SignalForge;

public sealed class Rule
{
    public string Id { get; }
    public string Severity { get; }
    internal string[] By { get; }
    internal TimeSpan Within { get; }
    internal Selector[] Stages { get; }
    internal bool Ordered { get; }
    internal int Threshold { get; }

    internal Rule(string id, string severity, string[] by, TimeSpan within, Selector[] stages,
                  bool ordered, int threshold)
    {
        Id = id;
        Severity = severity;
        By = by;
        Within = within;
        Stages = stages;
        Ordered = ordered;
        Threshold = threshold;
    }
}

internal sealed record Term(string Field, string Op, string? Value);

internal sealed class Selector(Term[] terms)
{
    internal bool Matches(SecurityEvent item)
    {
        foreach (Term term in terms)
        {
            string? actual = item.Get(term.Field);
            bool match = term.Op switch
            {
                "exists" => actual is not null,
                "eq" => actual == term.Value,
                "prefix" => actual?.StartsWith(term.Value!, StringComparison.Ordinal) == true,
                _ => false
            };
            if (!match)
                return false;
        }
        return true;
    }
}

public static class Rules
{
    public static IReadOnlyList<Rule> Load(string path)
    {
        using JsonDocument document = Inputs.OpenRuleFile(path);
        JsonElement root = document.RootElement;
        Inputs.Object(root, "version", "rules");
        _ = Inputs.Integer(Inputs.Required(root, "version"), 1, 1);
        var results = new List<Rule>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonElement element in Array(Inputs.Required(root, "rules"), 1, 128))
        {
            Rule rule = Decode(element);
            if (!ids.Add(rule.Id))
                throw new FormatException("duplicate rule ID");
            results.Add(rule);
        }
        return results.AsReadOnly();
    }

    private static Rule Decode(JsonElement element)
    {
        Inputs.Object(element, "id", "severity", "type", "by", "seconds", "stages", "count");
        string id = Inputs.Key(Inputs.Required(element, "id"));
        string severity = Inputs.Key(Inputs.Required(element, "severity"));
        if (severity is not ("low" or "medium" or "high"))
            throw new FormatException("invalid severity");
        string type = Inputs.Key(Inputs.Required(element, "type"));
        bool ordered = type switch
        {
            "sequence" => true,
            "threshold" => false,
            _ => throw new FormatException("unknown rule type")
        };
        string[] by = Array(Inputs.Required(element, "by"), 0, 4).Select(Inputs.Key).ToArray();
        if (by.Distinct(StringComparer.Ordinal).Count() != by.Length)
            throw new FormatException("duplicate grouping field");
        int seconds = Inputs.Integer(Inputs.Required(element, "seconds"), 1, 86400);
        Selector[] stages = Array(Inputs.Required(element, "stages"), ordered ? 2 : 1, ordered ? 8 : 1)
            .Select(ReadSelector).ToArray();
        int threshold = 0;
        if (!ordered)
            threshold = Inputs.Integer(Inputs.Required(element, "count"), 1, 100);
        else if (element.TryGetProperty("count", out _))
            throw new FormatException("sequence rule has an unexpected count");
        return new(id, severity, by, TimeSpan.FromSeconds(seconds), stages, ordered, threshold);
    }

    private static Selector ReadSelector(JsonElement element)
    {
        var terms = new List<Term>();
        foreach (JsonElement node in Array(element, 1, 8))
        {
            Inputs.Object(node, "field", "op", "value");
            string field = Inputs.Key(Inputs.Required(node, "field"));
            string op = Inputs.Key(Inputs.Required(node, "op"));
            if (op is not ("eq" or "prefix" or "exists"))
                throw new FormatException("unsupported predicate");
            string? value = null;
            if (op != "exists")
                value = Inputs.Text(Inputs.Required(node, "value"));
            else if (node.TryGetProperty("value", out _))
                throw new FormatException("exists accepts only field and op");
            terms.Add(new(field, op, value));
        }
        return new(terms.ToArray());
    }

    internal static JsonElement.ArrayEnumerator Array(JsonElement value, int min, int max)
    {
        if (value.ValueKind != JsonValueKind.Array ||
            value.GetArrayLength() < min || value.GetArrayLength() > max)
            throw new FormatException($"expected array length from {min} through {max}");
        return value.EnumerateArray();
    }
}
