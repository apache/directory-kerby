package org.haox.kerb.server;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Handles a server-side channel.
 */
public class KdcServerHandler extends SimpleChannelInboundHandler<Object> {

    private static final Logger logger = Logger.getLogger(
            KdcServerHandler.class.getName());

    @Override
    public void messageReceived(ChannelHandlerContext ctx, Object msg) throws Exception {
        logger.log(Level.INFO, "message received, msg:" + msg.toString());
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx,
            Throwable cause) throws Exception {
        // Close the connection when an exception is raised.
        logger.log(
                Level.WARNING,
                "Unexpected exception from downstream.",
                cause);
        ctx.close();
    }
}
