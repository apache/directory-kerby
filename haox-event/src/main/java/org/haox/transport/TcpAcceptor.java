package org.haox.transport;

import org.haox.event.Dispatcher;
import org.haox.event.Event;
import org.haox.event.EventHandler;
import org.haox.transport.event.TransportEventType;
import org.haox.transport.event.channel.TcpAddressBindEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

public class TcpAcceptor extends Acceptor {

    private boolean tcpNoDelay = true;

    @Override
    protected void doListen(InetSocketAddress socketAddress) {
        TcpAddressBindEvent event = new TcpAddressBindEvent(socketAddress);
        dispatch(event);
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
        TcpTransport transport = (TcpTransport) selectionKey.attachment();
        transport.onReadable();
        selectionKey.interestOps(SelectionKey.OP_WRITE);
    }

    void doWrite(SelectionKey selectionKey) throws IOException {
        TcpTransport transport = (TcpTransport) selectionKey.attachment();
        transport.onWriteable();
        selectionKey.interestOps(SelectionKey.OP_READ);
    }

    @Override
    public void handle(Event event) {
        if (event.getEventType() == TransportEventType.TCP_ADDRESS_BIND) {
            try {
                doBind((TcpAddressBindEvent) event);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public TransportEventType[] getInterestedEvents() {
        return new TransportEventType[] {
                TransportEventType.TCP_ADDRESS_BIND
        };
    }

    protected void doBind(TcpAddressBindEvent event) throws IOException {
        ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.configureBlocking(false);
        ServerSocket serverSocket = serverSocketChannel.socket();
        serverSocket.bind(event.getAddress());
        serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);
    }

}
