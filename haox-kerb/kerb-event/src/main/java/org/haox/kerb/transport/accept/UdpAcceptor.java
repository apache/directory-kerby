package org.haox.kerb.transport.accept;

import org.haox.kerb.transport.UdpTransport;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.util.HashMap;
import java.util.Map;

public class UdpAcceptor extends Acceptor {
    private String address;
    private short listenPort;
    private DatagramChannel serverSocketChannel = null;
    private Map<InetSocketAddress, UdpTransport> transports;

    public UdpAcceptor(String address, short listenPort) {
        super(address, listenPort);
        this.transports = new HashMap<InetSocketAddress, UdpTransport>();
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
            doRead(selectionKey);
        }
    }

    private void doRead(SelectionKey selectionKey) throws IOException {
        DatagramChannel datagramChannel =
                (DatagramChannel) selectionKey.channel();
        ByteBuffer recvBuffer = ByteBuffer.allocate(65536); // to optimize
        InetSocketAddress fromAddress = (InetSocketAddress) datagramChannel.receive(recvBuffer);
        if (fromAddress != null) {
            UdpTransport transport = transports.get(fromAddress);
            if (transport == null) {
                transport = new UdpTransport(datagramChannel, fromAddress);
                transports.put(fromAddress, transport);
            }
            transport.onInboundMessage(recvBuffer);
        }
    }
}
