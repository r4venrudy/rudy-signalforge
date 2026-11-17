namespace SignalForge;

public sealed class ReplayEngine
{
    private const int MaxGroups = 3000;
    private const int MaxAlerts = 20_000;
    private readonly record struct Group(string? First, string? Second, string? Third, string? Fourth);
    private sealed record State(LinkedListNode<(Group Key, DateTimeOffset Time)> Activity,
                                Sequence? Sequence, Threshold? Threshold);

    private sealed class Partition(Rule rule)
    {
        public Rule Rule { get; } = rule;
        private readonly Dictionary<Group, State> states = new();
        // Event times are nondecreasing. Moving an updated group to the back
        // keeps the oldest activation at the front without queuing duplicates.
        private readonly LinkedList<(Group Key, DateTimeOffset Time)> activity = new();

        public Evidence[]? Accept(SecurityEvent item, Evidence evidence)
        {
            while (activity.First is { } next && item.Time - next.Value.Time > Rule.Within)
            {
                states.Remove(next.Value.Key);
                activity.RemoveFirst();
            }
            var values = new string?[4];
            for (int index = 0; index < Rule.By.Length; index++)
            {
                values[index] = item.Get(Rule.By[index]);
                if (values[index] is null)
                    return null;
            }
            var key = new Group(values[0], values[1], values[2], values[3]);
            if (!states.TryGetValue(key, out State? state))
            {
                if (!Rule.Stages[0].Matches(item))
                    return null;
                if (states.Count == MaxGroups)
                    throw new FormatException($"active group limit exceeded for rule {Rule.Id}");
                var node = activity.AddLast((key, item.Time));
                state = Rule.Ordered
                    ? new(node, new Sequence(Rule.Stages, Rule.Within), null)
                    : new(node, null, new Threshold(Rule.Stages[0], Rule.Threshold, Rule.Within));
                states.Add(key, state);
            }
            else if (state.Activity.Value.Time != item.Time &&
                     Rule.Stages.Any(selector => selector.Matches(item)))
            {
                activity.Remove(state.Activity);
                state.Activity.Value = (key, item.Time);
                activity.AddLast(state.Activity);
            }
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
