package org.haox.transport.tcp;

import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.transport.Acceptor;
import org.haox.transport.event.AddressEvent;
import org.haox.transport.Transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

public class TcpAcceptor extends Acceptor {

    private boolean tcpNoDelay = true;

    public TcpAcceptor(StreamingDecoder streamingDecoder) {
        super(new TcpTransportHandler(streamingDecoder));
    }

    @Override
    protected void doListen(InetSocketAddress socketAddress) {
        AddressEvent event = TcpAddressEvent.createAddressBindEvent(socketAddress);
        dispatch(event);
    }

    @Override
    protected void dealKey(SelectionKey selectionKey) throws IOException {
        if (selectionKey.isAcceptable()) {
            doAccept(selectionKey);
        } else {
            super.dealKey(selectionKey);
        }
    }

    void doAccept(SelectionKey key) throws IOException {
        ServerSocketChannel server = (ServerSocketChannel) key.channel();
        SocketChannel channel;
        while ((channel = server.accept()) != null) {
            channel.configureBlocking(false);
            channel.socket().setTcpNoDelay(tcpNoDelay);
            channel.socket().setKeepAlive(true);

            Transport transport = new TcpTransport(channel,
                    ((TcpTransportHandler) transportHandler).getStreamingDecoder());
            channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE, transport);
            onNewTransport(transport);
        }
    }

    @Override
    public void handle(Event event) {
        if (event.getEventType() == TcpEventType.ADDRESS_BIND) {
            try {
                doBind((AddressEvent) event);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] {
                TcpEventType.ADDRESS_BIND
        };
    }

    protected void doBind(AddressEvent event) throws IOException {
        ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.configureBlocking(false);
        ServerSocket serverSocket = serverSocketChannel.socket();
        serverSocket.bind(event.getAddress());
        serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT, serverSocketChannel);
    }

}
