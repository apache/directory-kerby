package org.apache.kerby.has.server.web;


import org.apache.hadoop.classification.InterfaceAudience.Private;
import org.apache.hadoop.classification.InterfaceStability.Unstable;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.util.HasUtil;
import org.apache.kerby.has.server.HasServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.File;
import java.io.IOException;

@Private
@Unstable
public class ConfFilter implements Filter {
    public static final Logger LOG = LoggerFactory.getLogger(ConfFilter.class);
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {

        final HasServer hasServer = WebServer.getHasServerFromContext(
                servletRequest.getServletContext());
        HasConfig hasConfig;
        try {
            hasConfig = HasUtil.getHasConfig(
                    new File(hasServer.getConfDir(), "has-server.conf"));
            String isEnableConf = hasConfig.getEnableConf();
            if (!isEnableConf.equals("true")) {
                throw new IOException("The KDC has started, please stop KDC before setting.");
            }
            filterChain.doFilter(servletRequest, servletResponse);
        } catch (HasException e) {
            LOG.error(e.getMessage());
        }
    }

    @Override
    public void destroy() {

    }
}