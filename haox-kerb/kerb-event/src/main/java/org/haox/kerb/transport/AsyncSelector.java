package org.haox.kerb.transport;

import org.haox.kerb.event.NewTransportEvent;
import org.haox.kerb.handler.AsyncEventHandler;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;
import java.util.Set;

public abstract class AsyncSelector extends AsyncEventHandler {

    protected Selector selector;

    public AsyncSelector() {
        super();
    }

    protected void init() {
        super.init();

        try {
            selector = Selector.open();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    protected boolean loopOnce() {
        boolean checkResult = false;
        try {
            checkResult = checkAndProcess();
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            selectOnce();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return checkResult;
    }

    protected void selectOnce() throws IOException {
        if (selector.selectNow() > 0) {
            Set<SelectionKey> selectionKeys = selector.selectedKeys();
            Iterator<SelectionKey> iterator = selectionKeys.iterator();
            while (iterator.hasNext()) {
                SelectionKey selectionKey = iterator.next();
                iterator.remove();
                dealKey(selectionKey);
            }
        }
    }

    protected abstract void dealKey(SelectionKey selectionKey) throws IOException;

    protected void onNewTransport(Transport transport) {
        transport.setDispatcher(getDispatcher());
        getDispatcher().dispatch(new NewTransportEvent(transport));
    }

}
