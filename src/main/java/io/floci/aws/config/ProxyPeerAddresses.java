package io.floci.aws.config;

import io.vertx.core.net.SocketAddress;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/** Original peers of active, in-process TCP proxy connections. No caller headers are trusted. */
@ApplicationScoped
public class ProxyPeerAddresses {
    private final ConcurrentMap<Connection, Peer> peers = new ConcurrentHashMap<>();

    Runnable register(SocketAddress client, SocketAddress server, SocketAddress original) {
        Connection connection = key(client, server);
        Peer peer = new Peer(original);
        peers.put(connection, peer);
        return () -> peers.remove(connection, peer);
    }

    public SocketAddress resolve(SocketAddress remote, SocketAddress local) {
        if (remote == null || local == null) {
            return remote;
        }
        Peer peer = peers.get(key(remote, local));
        return peer == null ? remote : peer.address;
    }

    private static Connection key(SocketAddress client, SocketAddress server) {
        return new Connection(client.host(), client.port(), server.host(), server.port());
    }

    private record Connection(String clientHost, int clientPort, String serverHost, int serverPort) {}

    // Identity equality prevents a delayed close from removing a reused socket tuple.
    private static final class Peer {
        private final SocketAddress address;

        private Peer(SocketAddress address) {
            this.address = address;
        }
    }
}
