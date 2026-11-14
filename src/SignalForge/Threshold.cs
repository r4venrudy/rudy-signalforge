namespace SignalForge;

internal sealed class Threshold(Selector selector, int count, TimeSpan within)
{
    private readonly Queue<Evidence> recent = new();

    public Evidence[]? Accept(SecurityEvent item, Evidence reference)
    {
        while (recent.TryPeek(out Evidence? previous) && item.Time - previous.Time > within)
            recent.Dequeue();
        if (!selector.Matches(item))
            return null;
        bool crossing = recent.Count < count;
        recent.Enqueue(reference);
        if (recent.Count > count)
            recent.Dequeue();
        return crossing && recent.Count == count ? recent.ToArray() : null;
    }
}
