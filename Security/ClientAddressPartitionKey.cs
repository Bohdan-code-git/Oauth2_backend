using System.Net;
using System.Net.Sockets;

public static class ClientAddressPartitionKey
{
    public static string For(IPAddress? address)
    {
        if (address is null)
            return "unknown";

        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
            return address.ToString();

        var prefix = address.GetAddressBytes();
        Array.Clear(prefix, 8, 8);
        return new IPAddress(prefix).ToString() + "/64";
    }

    public static string For(IPAddress? remoteAddress, string? forwardedFor, bool trustForwardedFor)
    {
        if (trustForwardedFor && !string.IsNullOrWhiteSpace(forwardedFor))
        {
            var firstAddress = forwardedFor.Split(',', 2)[0].Trim();
            if (IPAddress.TryParse(firstAddress, out var clientAddress))
                return For(clientAddress);
        }

        return For(remoteAddress);
    }
}
