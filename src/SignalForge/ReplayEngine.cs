namespace SignalForge;

public sealed class ReplayEngine
{
    private const int MaxGroups = 3000;
    private const int MaxAlerts = 20_000;
    private sealed record State(DateTimeOffset Last, Sequence? Sequence, Threshold? Threshold);

    private sealed class Partition(Rule rule)
    {
        public Rule Rule { get; } = rule;
        public Dictionary<(string?, string?, string?, string?), State> States { get; } = new();
        public Queue<((string?, string?, string?, string?) Key, DateTimeOffset Time)> Visits { get; } = new();

        public Evidence[]? Accept(SecurityEvent item, Evidence evidence)
        {
            while (Visits.TryPeek(out var next) && item.Time - next.Time > Rule.Within)
            {
                Visits.Dequeue();
                if (States.TryGetValue(next.Key, out State? current) && current.Last == next.Time)
                    States.Remove(next.Key);
            }
            var values = new string?[4];
            for (int index = 0; index < Rule.By.Length; index++)
            {
                values[index] = item.Get(Rule.By[index]);
                if (values[index] is null)
                    return null;
            }
            var key = (values[0], values[1], values[2], values[3]);
            if (!States.TryGetValue(key, out State? state))
            {
                if (!Rule.Stages[0].Matches(item))
                    return null;
                if (States.Count == MaxGroups)
                    throw new FormatException($"active group limit exceeded for rule {Rule.Id}");
                state = Rule.Ordered
                    ? new(item.Time, new Sequence(Rule.Stages, Rule.Within), null)
                    : new(item.Time, null, new Threshold(Rule.Stages[0], Rule.Threshold, Rule.Within));
                Visits.Enqueue((key, item.Time));
                States.Add(key, state);
            }
            else if (state.Last != item.Time && Rule.Stages.Any(selector => selector.Matches(item)))
            {
                States[key] = state with { Last = item.Time };
                Visits.Enqueue((key, item.Time));
            }
            // The CLI returns an input error rather than an incomplete result.
            if (Visits.Count > 20_000)
                throw new FormatException($"window activity limit exceeded for rule {Rule.Id}");
            return state.Sequence is { } sequence
                ? sequence.Accept(item, evidence) : state.Threshold!.Accept(item, evidence);
        }
    }

    public IReadOnlyList<Alert> Run(IReadOnlyList<Rule> rules, IEnumerable<SecurityEvent> events)
    {
        Partition[] partitions = rules.Select(rule => new Partition(rule)).ToArray();
        var result = new List<Alert>();
        DateTimeOffset? previous = null;
        int count = 0;
        var seen = new HashSet<(string, string)>();
        foreach (SecurityEvent item in events)
        {
            if (previous > item.Time || !seen.Add((item.Source, item.Id)))
                throw new FormatException("replay requires ordered events with unique identities");
            previous = item.Time;
            if (++count > Inputs.MaxEvents || (long)count * partitions.Length > 8_000_000)
                throw new FormatException("replay work limit exceeded");
            var evidence = new Evidence(item.Time.ToUniversalTime(), item.Source, item.Id);
            foreach (Partition partition in partitions)
            {
                Evidence[]? matches = partition.Accept(item, evidence);
                if (matches is null)
                    continue;
                if (result.Count == MaxAlerts)
                    throw new FormatException("alert limit exceeded");
                Rule rule = partition.Rule;
                result.Add(new(rule.Id, rule.Severity, rule.By.Select(field => item.Get(field)!).ToArray(),
                               evidence.Time, matches));
            }
        }
        return result;
    }
}
