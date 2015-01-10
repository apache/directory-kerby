package org.apache.haox.transport.tcp;

import org.apache.haox.event.AbstractEventHandler;
import org.apache.haox.event.Event;
import org.apache.haox.event.EventType;
import org.apache.haox.transport.Acceptor;
import org.apache.haox.transport.Transport;
import org.apache.haox.transport.event.AddressEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

public class TcpAcceptor extends Acceptor {

    public TcpAcceptor(StreamingDecoder streamingDecoder) {
        this(new TcpTransportHandler(streamingDecoder));
    }

    public TcpAcceptor(TcpTransportHandler transportHandler) {
        super(transportHandler);

        setEventHandler(new AbstractEventHandler() {
            @Override
            protected void doHandle(Event event) throws Exception {
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
        });
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
            // Quick fix: avoid exception during exiting
            if (! selector.isOpen()) {
                channel.close();
                break;
            };

            channel.configureBlocking(false);
            channel.socket().setTcpNoDelay(true);
            channel.socket().setKeepAlive(true);

            Transport transport = new TcpTransport(channel,
                    ((TcpTransportHandler) transportHandler).getStreamingDecoder());

            if (! selector.isOpen()) {
                break;
            }
            channel.register(selector,
                SelectionKey.OP_READ | SelectionKey.OP_WRITE, transport);
            onNewTransport(transport);
        }
    }

    protected void doBind(AddressEvent event) throws IOException {
        ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.configureBlocking(false);
        ServerSocket serverSocket = serverSocketChannel.socket();
        serverSocket.bind(event.getAddress());
        serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT, serverSocketChannel);
    }

}
