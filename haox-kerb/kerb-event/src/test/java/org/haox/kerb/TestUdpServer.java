package org.haox.kerb;

import junit.framework.Assert;
import org.haox.kerb.dispatch.AsyncDispatcher;
import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;
import org.haox.kerb.event.MessageEvent;
import org.haox.kerb.handler.AsyncMessageHandler;
import org.haox.kerb.handler.MessageHandler;
import org.haox.kerb.transport.accept.Acceptor;
import org.haox.kerb.transport.accept.UdpAcceptor;
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
        AsyncDispatcher serverDispatcher = new AsyncDispatcher();
        serverDispatcher.start();

        MessageHandler messageHandler = new MessageHandler() {
            @Override
            public void process(Event event) {
                MessageEvent msgEvent = (MessageEvent) event;
                if (msgEvent.getEventType() == EventType.NEW_INBOUND_MESSAGE) {
                    msgEvent.getTransport().postMessage(msgEvent.getMessage());
                } else if (msgEvent.getEventType() == EventType.NEW_OUTBOUND_MESSAGE) {
                    try {
                        msgEvent.getTransport().sendMessage(msgEvent.getMessage());
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        };
        serverDispatcher.register(new AsyncMessageHandler(messageHandler));

        Acceptor acceptor = new UdpAcceptor();
        serverDispatcher.register(acceptor);

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
