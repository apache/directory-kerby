package org.haox.transport.tcp;

import java.nio.ByteBuffer;

public interface StreamingDecoder {

    public static interface DecodingResult {

    }

    /**
     * OK, enough data is ready, a message can be out
     */
    public static class MessageResult implements DecodingResult {
        private int messageLength;

        public MessageResult(int messageLength) {
            this.messageLength = messageLength;
        }

        public int getMessageLength() {
            return messageLength;
        }
    }

    /**
     * Need more data to be available, with estimated message length given
     */
    public static class MoreDataResult implements DecodingResult {
        private int estimatedMessageLength;

        public MoreDataResult(int estimatedMessageLength) {
            this.estimatedMessageLength = estimatedMessageLength;
        }

        public int getEstimatedMessageLength() {
            return estimatedMessageLength;
        }
    }

    public abstract DecodingResult decode(ByteBuffer streaming);
}
