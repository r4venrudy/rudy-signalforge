using System.Text.Json;

namespace SignalForge;

public sealed record ExpectationResult(bool Passed, int Expected, int Actual, int Missing, int Unexpected);

public static class Expectations
{
    private sealed record Match(string Rule, string[] Group, (string Source, string Id)[] Evidence);

    private static string Key(Match match) => JsonSerializer.Serialize(new
    {
        match.Rule, match.Group,
        Evidence = match.Evidence.Select(eventId => new[] { eventId.Source, eventId.Id })
    });

    public static ExpectationResult Verify(string path, IReadOnlyList<Alert> alerts)
    {
        using JsonDocument document = Inputs.OpenRuleFile(path);
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        int expected = 0;
        foreach (JsonElement item in Rules.Array(document.RootElement, 0, 20_000))
        {
            Inputs.Object(item, "rule", "group", "evidence");
            string rule = Inputs.Key(Inputs.Required(item, "rule"));
            string[] group = Rules.Array(Inputs.Required(item, "group"), 0, 4)
                .Select(item => Inputs.Text(item)).ToArray();
            var ids = Rules.Array(Inputs.Required(item, "evidence"), 1, 100).Select(item =>
            {
                Inputs.Object(item, "source", "id");
                return (Inputs.Key(Inputs.Required(item, "source")), Inputs.Key(Inputs.Required(item, "id")));
            }).ToArray();
            string key = Key(new(rule, group, ids));
            counts[key] = counts.GetValueOrDefault(key) + 1;
            expected++;
        }
        int unexpected = 0;
        foreach (Alert alert in alerts)
        {
            string key = Key(new(alert.Rule, alert.Group, alert.Evidence.Select(e => (e.Source, e.Id)).ToArray()));
            if (!counts.TryGetValue(key, out int count) || count == 0)
                unexpected++;
            else
                counts[key] = count - 1;
        }
        int missing = counts.Values.Sum();
        return new(missing == 0 && unexpected == 0, expected, alerts.Count, missing, unexpected);
    }
}
