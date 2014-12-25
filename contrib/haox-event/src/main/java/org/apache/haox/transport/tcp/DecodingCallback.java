package org.apache.haox.transport.tcp;

public interface DecodingCallback {

    /**
     * OK, enough data is ready, a message can be out
     */
    public void onMessageComplete(int messageLength);

    /**
     * Need more data to be available
     */
    public void onMoreDataNeeded();

    /**
     * Need more data to be available, with determined more data length given
     */
    public void onMoreDataNeeded(int needDataLength);
}
