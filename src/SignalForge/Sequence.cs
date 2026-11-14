namespace SignalForge;

internal sealed class Sequence(Selector[] stages, TimeSpan within)
{
    // The latest starting prefix dominates older prefixes of the same length.
    // Advancing from longest to shortest prevents one event filling two stages.
    private readonly Evidence[]?[] prefixes = new Evidence[stages.Length - 1][];

    public Evidence[]? Accept(SecurityEvent item, Evidence reference)
    {
        for (int index = 0; index < prefixes.Length; index++)
            if (prefixes[index] is { } old && item.Time - old[0].Time > within)
                prefixes[index] = null;

        Evidence[]? result = null;
        for (int index = prefixes.Length - 1; index >= 0; index--)
        {
            if (prefixes[index] is not { } matches || !stages[index + 1].Matches(item))
                continue;
            if (index + 1 == prefixes.Length)
                result = [.. matches, reference];
            else if (prefixes[index + 1] is not { } incumbent || matches[0].Time >= incumbent[0].Time)
                prefixes[index + 1] = [.. matches, reference];
        }
        if (stages[0].Matches(item))
            prefixes[0] = [reference];
        return result;
    }
}
