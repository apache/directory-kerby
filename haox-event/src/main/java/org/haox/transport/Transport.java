package org.haox.transport;

import org.haox.event.Dispatcher;
import org.haox.transport.buffer.TransBuffer;
import org.haox.transport.event.TransportEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public abstract class Transport {
    private InetSocketAddress remoteAddress;
    protected Dispatcher dispatcher;
    private Object attachment;

    protected TransBuffer sendBuffer;

    private int readableCount = 0;
    private int writableCount = 0;

    public Transport(InetSocketAddress remoteAddress) {
        this.remoteAddress = remoteAddress;
        this.sendBuffer = new TransBuffer();
    }

    public void setDispatcher(Dispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    public InetSocketAddress getRemoteAddress() {
        return remoteAddress;
    }

    public void sendMessage(ByteBuffer message) {
        sendBuffer.write(message);
        dispatcher.dispatch(TransportEvent.createWritableTransportEvent(this));
    }

    public void onWriteable() throws IOException {
        this.writableCount ++;

        if (! sendBuffer.isEmpty()) {
            ByteBuffer message = sendBuffer.read();
            if (message != null) {
                sendOutMessage(message);
            }
        }
    }

    public void onReadable() throws IOException {
        this.readableCount++;
    }

    protected abstract void sendOutMessage(ByteBuffer message) throws IOException;

    public void setAttachment(Object attachment) {
        this.attachment = attachment;
    }

    public Object getAttachment() {
        return attachment;
    }
}
