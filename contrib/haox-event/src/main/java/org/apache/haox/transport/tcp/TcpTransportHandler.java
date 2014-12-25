package org.apache.haox.transport.tcp;

import org.apache.haox.event.Event;
import org.apache.haox.event.EventType;
import org.apache.haox.transport.Transport;
import org.apache.haox.transport.event.TransportEventType;
import org.apache.haox.transport.TransportHandler;
import org.apache.haox.transport.event.TransportEvent;

import java.io.IOException;
import java.nio.channels.SelectionKey;

public class TcpTransportHandler extends TransportHandler {

    private StreamingDecoder streamingDecoder;

    public TcpTransportHandler(StreamingDecoder streamingDecoder) {
        this.streamingDecoder = streamingDecoder;
    }

    public StreamingDecoder getStreamingDecoder() {
        return streamingDecoder;
    }

    @Override
    public EventType[] getInterestedEvents() {
        return new TransportEventType[] {
                TransportEventType.TRANSPORT_READABLE,
                TransportEventType.TRANSPORT_WRITABLE
        };
    }

    @Override
    protected void doHandle(Event event) throws Exception {
        EventType eventType = event.getEventType();
        TransportEvent te = (TransportEvent) event;
        Transport transport = te.getTransport();
        if (eventType == TransportEventType.TRANSPORT_READABLE) {
            transport.onReadable();
        } else if (eventType == TransportEventType.TRANSPORT_WRITABLE) {
            transport.onWriteable();
        }
    }

    @Override
    public void helpHandleSelectionKey(SelectionKey selectionKey) throws IOException {
        if (selectionKey.isReadable()) {
            selectionKey.interestOps(SelectionKey.OP_READ | SelectionKey.OP_WRITE);
            TcpTransport transport = (TcpTransport) selectionKey.attachment();
            dispatch(TransportEvent.createReadableTransportEvent(transport));
        } else if (selectionKey.isWritable()) {
            selectionKey.interestOps(SelectionKey.OP_READ);
            TcpTransport transport = (TcpTransport) selectionKey.attachment();
            dispatch(TransportEvent.createWritableTransportEvent(transport));
        }
    }
}

