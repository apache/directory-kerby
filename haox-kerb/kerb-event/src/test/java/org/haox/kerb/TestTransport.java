package org.haox.kerb;

import junit.framework.Assert;
import org.haox.kerb.dispatch.AsyncDispatcher;
import org.haox.kerb.event.EventType;
import org.haox.kerb.event.MessageEvent;
import org.haox.kerb.handler.SimpleMessageHandler;
import org.haox.kerb.message.Message;
import org.haox.kerb.transport.Transport;
import org.haox.kerb.transport.accept.Acceptor;
import org.haox.kerb.transport.accept.UdpAcceptor;
import org.haox.kerb.transport.connect.Connector;
import org.haox.kerb.transport.connect.UdpConnector;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

public class TestTransport {
    private String serverHost = "localhost";
    private short serverPort = 8181;

    private AsyncDispatcher serverDispatcher;
    private Acceptor acceptor;
    private AsyncDispatcher clientDispatcher;

    private String TEST_MESSAGE = "Hello world!";
    private String clientRecvedMessage;

    @Before
    public void setUp() {
        setUpServerSide();
        setUpClientSide();
    }

    private void setUpServerSide() {
        serverDispatcher = new AsyncDispatcher();
        serverDispatcher.register(new SimpleMessageHandler() {
            @Override
            public void handleMessage(MessageEvent event) {
                if (event.getEventType() == EventType.NEW_INBOUND_MESSAGE) {
                    event.getTransport().postMessage(event.getMessage());
                } else if (event.getEventType() == EventType.NEW_OUTBOUND_MESSAGE) {
                    try {
                        event.getTransport().sendMessage(event.getMessage());
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        });
        serverDispatcher.start();
    }

    private void setUpClientSide() {
        clientDispatcher = new AsyncDispatcher();
        clientDispatcher.register(new SimpleMessageHandler() {
            @Override
            public void handleMessage(MessageEvent event) {
                if (event.getEventType() == EventType.NEW_INBOUND_MESSAGE) {
                    clientRecvedMessage = new String(event.getMessage().getContent().array());
                } else if (event.getEventType() == EventType.NEW_OUTBOUND_MESSAGE) {
                    try {
                        event.getTransport().sendMessage(event.getMessage());
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        });
        clientDispatcher.start();
    }

    @Test
    public void testUdpTransport() throws IOException, InterruptedException {
        acceptor = new UdpAcceptor(serverHost, serverPort);
        acceptor.setDispatcher(serverDispatcher);
        acceptor.start();

        Connector connector = new UdpConnector();
        connector.setDispatcher(clientDispatcher);
        Transport transport = connector.connect(serverHost, serverPort);
        transport.postMessage(new Message(ByteBuffer.wrap(TEST_MESSAGE.getBytes())));

        while (clientRecvedMessage == null) {
            Thread.currentThread().wait(1000);
        }
        Assert.assertEquals(TEST_MESSAGE, clientRecvedMessage);
    }

    @After
    public void cleanUp() {
        acceptor.stop();
        serverDispatcher.stop();
        clientDispatcher.stop();
    }
}
