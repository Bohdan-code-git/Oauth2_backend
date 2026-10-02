using System.Net;
using Xunit;

public sealed class RequestAbuseGuardTests
{
    [Fact]
    public void ClientPartitionKeyKeepsIpv6AndIpv4AddressesDistinct()
    {
        var nativeIpv6 = ClientAddressPartitionKey.For(IPAddress.Parse("2001:db8:1::1"));
        var mappedIpv6 = ClientAddressPartitionKey.For(IPAddress.Parse("::ffff:192.0.2.1"));
        var ipv4 = ClientAddressPartitionKey.For(IPAddress.Parse("192.0.2.1"));
        var anotherIpv4 = ClientAddressPartitionKey.For(IPAddress.Parse("0.0.0.1"));

        Assert.Equal("192.0.2.1", mappedIpv6);
        Assert.Equal(ipv4, mappedIpv6);
        Assert.NotEqual(anotherIpv4, mappedIpv6);
        Assert.StartsWith("2001:db8:1:", nativeIpv6, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NativeIpv6ClientsShareTheirSlash64RateLimitPartition()
    {
        var first = ClientAddressPartitionKey.For(IPAddress.Parse("2001:db8:1::1"));
        var second = ClientAddressPartitionKey.For(IPAddress.Parse("2001:db8:1::ffff"));
        var otherPrefix = ClientAddressPartitionKey.For(IPAddress.Parse("2001:db8:2::1"));

        Assert.Equal(first, second);
        Assert.NotEqual(first, otherPrefix);
    }

    [Fact]
    public void RenderRateLimitUsesTheFirstForwardedForClientAddress()
    {
        var key = ClientAddressPartitionKey.For(
            IPAddress.Parse("10.0.0.8"),
            "198.51.100.24, 10.0.0.8",
            trustForwardedFor: true);

        Assert.Equal("198.51.100.24", key);
    }

    [Fact]
    public void ForwardedForIsIgnoredOutsideRenderAndWhenMalformed()
    {
        var remoteAddress = IPAddress.Parse("10.0.0.8");

        Assert.Equal(
            "10.0.0.8",
            ClientAddressPartitionKey.For(remoteAddress, "198.51.100.24", trustForwardedFor: false));
        Assert.Equal(
            "10.0.0.8",
            ClientAddressPartitionKey.For(remoteAddress, "spoofed", trustForwardedFor: true));
    }
}
