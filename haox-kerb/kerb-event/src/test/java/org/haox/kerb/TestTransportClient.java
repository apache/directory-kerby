package org.haox.kerb;

import org.haox.kerb.dispatch.AsyncDispatcher;
import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;
import org.haox.kerb.event.MessageEvent;
import org.haox.kerb.handler.AsyncMessageHandler;
import org.haox.kerb.handler.AsyncTransportHandler;
import org.haox.kerb.handler.MessageHandler;
import org.haox.kerb.handler.TransportHandler;
import org.haox.kerb.message.Message;
import org.haox.kerb.transport.Transport;
import org.haox.kerb.transport.connect.Connector;
import org.haox.kerb.transport.connect.UdpConnector;

import java.io.IOException;
import java.nio.ByteBuffer;

public class TestTransportClient {
    private String serverHost = "127.0.0.1";
    private short serverPort = 8181;

    private Connector connector;
    private AsyncDispatcher clientDispatcher;
    private TransportHandler transportHandler;
    private Transport transport;

    private String TEST_MESSAGE = "Hello world!";
    private String clientRecvedMessage;

    public void setUp() throws IOException {
        setUpClientSide();
    }

    private void setUpClientSide() throws IOException {
        clientDispatcher = new AsyncDispatcher();
        clientDispatcher.start();

        MessageHandler messageHandler = new MessageHandler() {
            @Override
            public void process(Event event) {
                MessageEvent msgEvent = (MessageEvent) event;
                if (msgEvent.getEventType() == EventType.NEW_INBOUND_MESSAGE) {
                    synchronized (TestTransportClient.this) {
                        clientRecvedMessage = new String(msgEvent.getMessage().getContent().array());
                        System.out.println("Recved clientRecvedMessage: " + clientRecvedMessage);
                    }
                } else if (msgEvent.getEventType() == EventType.NEW_OUTBOUND_MESSAGE) {
                    try {
                        msgEvent.getTransport().sendMessage(msgEvent.getMessage());
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        };
        clientDispatcher.register(new AsyncMessageHandler(messageHandler));

        connector = new UdpConnector();
        clientDispatcher.register(connector);
        transportHandler = new TransportHandler() {
            @Override
            protected void onNewTransport(Transport transport) {
                synchronized (TestTransportClient.this) {
                    TestTransportClient.this.transport = transport;
                }
            }
        };
        clientDispatcher.register(new AsyncTransportHandler(transportHandler));

        connector.connect(serverHost, serverPort);
    }

    public void testUdpTransport() throws IOException {
        setUp();

        while (true) {
            synchronized (this) {
                if (transport != null) {
                    transport.postMessage(new Message(ByteBuffer.wrap(TEST_MESSAGE.getBytes())));
                }
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static void main(String[] args) throws IOException {
        TestTransportClient client = new TestTransportClient();
        client.testUdpTransport();
    }
}
