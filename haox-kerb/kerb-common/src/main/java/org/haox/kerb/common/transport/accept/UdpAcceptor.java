package org.haox.kerb.common.transport.accept;

import org.haox.kerb.common.transport.KrbTransport;
import org.haox.kerb.common.transport.UdpTransport;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;

public abstract class UdpAcceptor extends KrbAcceptor {
    private String address;
    private short listenPort;
    DatagramChannel serverSocketChannel = null;
    Selector selector = null;

    public UdpAcceptor(String address, short listenPort) {
        super(address, listenPort);
    }

    @Override
    protected void doStart() throws IOException {
        super.doStart();

        serverSocketChannel = DatagramChannel.open();
        serverSocketChannel.configureBlocking(false);
        DatagramSocket serverSocket = serverSocketChannel.socket();
        serverSocket.bind(new InetSocketAddress(listenPort));
        serverSocketChannel.register(selector, SelectionKey.OP_READ);
    }

    @Override
    protected void dealKey(SelectionKey selectionKey) throws IOException {
        if (selectionKey.isReadable()) {
            DatagramChannel datagramChannel =
                    (DatagramChannel) selectionKey.channel();
            KrbTransport transport = new UdpTransport(datagramChannel, false);
            onNewTransport(transport);
            //transport.onReadable();
        }
    }
}
