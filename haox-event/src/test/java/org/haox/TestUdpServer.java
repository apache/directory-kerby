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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

public class TestUdpServer extends TestUdpBase {

    private EventHub eventHub;

    @Before
    public void setUp() throws IOException {
        setUpServer();
    }

    private void setUpServer() throws IOException {
        eventHub = new EventHub();

        MessageHandler messageHandler = new MessageHandler(eventHub) {
            @Override
            protected void doHandle(Event event) throws Exception {
                MessageEvent msgEvent = (MessageEvent) event;
                if (msgEvent.getEventType() == TransportEventType.INBOUND_MESSAGE) {
                    msgEvent.getTransport().sendMessage(msgEvent.getMessage());
                }
            }
        };
        eventHub.register(messageHandler);

        Acceptor acceptor = new UdpAcceptor(eventHub);
        eventHub.register((InternalEventHandler) acceptor);

        eventHub.start();
        acceptor.listen(serverHost, serverPort);
    }

    @Test
    public void testUdpTransport() throws IOException, InterruptedException {
        DatagramChannel socketChannel = DatagramChannel.open();
        socketChannel.configureBlocking(true);
        SocketAddress sa = new InetSocketAddress(serverHost, serverPort);
        socketChannel.send(ByteBuffer.wrap(TEST_MESSAGE.getBytes()), sa);
        ByteBuffer byteBuffer = ByteBuffer.allocate(65536);
        socketChannel.receive(byteBuffer);
        byteBuffer.flip();
        clientRecvedMessage = recvBuffer2String(byteBuffer);

        Assert.assertEquals(TEST_MESSAGE, clientRecvedMessage);
    }

    @After
    public void cleanup() {
        eventHub.stop();
    }
}
