package org.haox;

import junit.framework.Assert;
import org.haox.event.Event;
import org.haox.event.EventHandler;
import org.haox.event.EventHub;
import org.haox.event.InternalEventHandler;
import org.haox.transport.Acceptor;
import org.haox.transport.MessageHandler;
import org.haox.transport.UdpAcceptor;
import org.haox.transport.event.MessageEvent;
import org.haox.transport.event.TransportEventType;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

public class TestUdpServer extends TestUdpBase {

    @Before
    public void setUp() throws IOException {
        setUpServer();
    }

    private void setUpServer() throws IOException {
        EventHub eventHub = new EventHub();
        eventHub.start();

        MessageHandler messageHandler = new MessageHandler(eventHub) {
            @Override
            protected void doHandle(Event event) throws Exception {
                MessageEvent msgEvent = (MessageEvent) event;
                if (msgEvent.getEventType() == TransportEventType.INBOUND_MESSAGE) {
                    msgEvent.getTransport().sendMessage(msgEvent.getMessage());
                } else if (msgEvent.getEventType() == TransportEventType.OUTBOUND_MESSAGE) {
                    msgEvent.getTransport().sendMessage(msgEvent.getMessage());
                }
            }
        };
        eventHub.register(messageHandler);

        Acceptor acceptor = new UdpAcceptor(eventHub);
        eventHub.register((InternalEventHandler) acceptor);
        acceptor.listen(serverHost, serverPort);
    }

    @Test
    public void testUdpTransport() throws IOException, InterruptedException {
        Thread.sleep(1000);

        DatagramChannel socketChannel = DatagramChannel.open();
        socketChannel.configureBlocking(true);
        SocketAddress sa = new InetSocketAddress(serverHost, serverPort);
        socketChannel.connect(sa);
        socketChannel.write(ByteBuffer.wrap(TEST_MESSAGE.getBytes()));
        ByteBuffer byteBuffer = ByteBuffer.allocate(65536);
        socketChannel.read(byteBuffer);
        byteBuffer.flip();
        clientRecvedMessage = recvBuffer2String(byteBuffer);

        Assert.assertEquals(TEST_MESSAGE, clientRecvedMessage);
    }
}
