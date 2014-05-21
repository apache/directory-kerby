package org.haox.kerb.transport.connect;

import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;
import org.haox.kerb.event.channel.TcpAddressConnectEvent;
import org.haox.kerb.transport.TcpTransport;
import org.haox.kerb.transport.Transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

public class TcpConnector extends Connector {

    public TcpConnector() {
        super();
    }

    @Override
    protected void doConnect(InetSocketAddress sa) throws IOException {
        TcpAddressConnectEvent event = new TcpAddressConnectEvent(sa);
        getDispatcher().dispatch(event);
    }

    @Override
    public void process(Event event) throws IOException {
        switch (event.getEventType()) {
            case TCP_ADDRESS_CONNECT:
                doConnect((TcpAddressConnectEvent) event);
        }
    }

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] {
                EventType.TCP_ADDRESS_CONNECT
        };
    }

    private void doConnect(TcpAddressConnectEvent event) throws IOException {
        SocketChannel channel = SocketChannel.open();
        channel.configureBlocking(false);
        channel.connect(event.getAddress());
        channel.register(selector, SelectionKey.OP_CONNECT|SelectionKey.OP_READ|SelectionKey.OP_WRITE);
    }

    @Override
    protected void dealKey(SelectionKey selectionKey) throws IOException {
        if (selectionKey.isConnectable()) {
            doConnect(selectionKey);
        } else if (selectionKey.isReadable()) {
            doRead(selectionKey);
        } else if (selectionKey.isWritable()) {
            doWrite(selectionKey);
        }
    }

    void doConnect(SelectionKey key) throws IOException {
        SocketChannel channel = (SocketChannel) key.channel();
        if (channel.isConnectionPending()) {
            channel.finishConnect();
        }

        channel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
        Transport transport = new TcpTransport(channel, true);
        key.attach(transport);
        onNewTransport(transport);
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

}
