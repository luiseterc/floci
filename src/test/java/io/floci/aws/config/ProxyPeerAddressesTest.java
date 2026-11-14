package io.floci.aws.config;

import io.vertx.core.net.SocketAddress;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ProxyPeerAddressesTest {
    private final ProxyPeerAddresses peers = new ProxyPeerAddresses();
    private final SocketAddress client = SocketAddress.inetSocketAddress(32000, "127.0.0.1");
    private final SocketAddress server = SocketAddress.inetSocketAddress(4510, "127.0.0.1");
    private final SocketAddress guest = SocketAddress.inetSocketAddress(41000, "10.93.1.10");

    @Test
    void onlyTheExactActiveConnectionResolvesToItsOriginalPeer() {
        assertEquals(client, peers.resolve(client, server));
        Runnable remove = peers.register(client, server, guest);
        assertEquals(guest, peers.resolve(client, server));
        assertEquals(client, peers.resolve(client, SocketAddress.inetSocketAddress(4511, "127.0.0.1")));
        SocketAddress another = SocketAddress.inetSocketAddress(32001, "127.0.0.1");
        assertEquals(another, peers.resolve(another, server));
        assertEquals(client, peers.resolve(client, SocketAddress.inetSocketAddress(4510, "127.0.0.2")));
        remove.run();
        assertEquals(client, peers.resolve(client, server));
        assertEquals(client, peers.resolve(client, null));
        assertNull(peers.resolve(null, server));
    }

    @Test
    void delayedCloseCannotRemoveAReusedSocketTuple() {
        Runnable old = peers.register(client, server, guest);
        SocketAddress next = SocketAddress.inetSocketAddress(41001, "10.93.1.11");
        Runnable current = peers.register(client, server, next);
        old.run();
        assertEquals(next, peers.resolve(client, server));
        current.run();
        assertEquals(client, peers.resolve(client, server));
    }
}
