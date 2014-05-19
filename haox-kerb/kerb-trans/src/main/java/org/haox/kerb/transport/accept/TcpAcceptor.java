package org.haox.kerb.transport.accept;

import org.haox.kerb.transport.Transport;
import org.haox.kerb.transport.TcpTransport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

public abstract class TcpAcceptor extends Acceptor {
    ServerSocketChannel serverSocketChannel = null;
    private boolean tcpNoDelay = true;

    public TcpAcceptor(String address, short listenPort) {
        super(address, listenPort);
    }

    @Override
    protected void doStart() throws IOException {
        super.doStart();

        serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.configureBlocking(false);
        ServerSocket serverSocket = serverSocketChannel.socket();
        serverSocket.bind(new InetSocketAddress(listenPort));
        serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);
    }

    @Override
    protected void dealKey(SelectionKey selectionKey) throws IOException {
        if (selectionKey.isAcceptable()) {
            doAccept(selectionKey);
        } else if (selectionKey.isReadable()) {
            doRead(selectionKey);
        } else if (selectionKey.isWritable()) {
            doWrite(selectionKey);
        }
    }

    void doAccept(SelectionKey key) throws IOException {
        ServerSocketChannel server = (ServerSocketChannel) key.channel();
        SocketChannel channel;
        while ((channel = server.accept()) != null) {
            channel.configureBlocking(false);
            channel.socket().setTcpNoDelay(tcpNoDelay);
            channel.socket().setKeepAlive(true);
            channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);

            Transport transport = new TcpTransport(channel, false);
            key.attach(transport);

            onNewTransport(transport);
        }
    }

    void doRead(SelectionKey selectionKey) throws IOException {
        Transport transport = (Transport) selectionKey.attachment();
        transport.onReadable();
        selectionKey.interestOps(SelectionKey.OP_WRITE);
    }

    void doWrite(SelectionKey selectionKey) throws IOException {
        Transport transport = (Transport) selectionKey.attachment();
        transport.onWriteable();
        selectionKey.interestOps(SelectionKey.OP_READ);
    }
}
