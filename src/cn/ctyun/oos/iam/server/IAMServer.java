package cn.ctyun.oos.iam.server;

import java.lang.management.ManagementFactory;

import javax.management.MBeanServer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.jmx.MBeanContainer;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.nio.SelectChannelConnector;
import org.eclipse.jetty.server.ssl.SslSelectChannelConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

import cn.ctyun.common.Consts;
import cn.ctyun.common.Program;
import cn.ctyun.common.utils.LogUtils;
import cn.ctyun.oos.iam.server.conf.IamServerConfig;
import common.util.GetOpt;

/**
 * IAM服务启动程序
 */
public class IAMServer implements Program {
    static {
        System.setProperty("log4j.log.app", "iam");
    }
    private static final Log log = LogFactory.getLog(IAMServer.class);
    
    public static void main(String[] args) throws Exception {
        new IAMServer().exec(args);
    }
    
    @Override
    public String usage() {
        return "Usage: \n";
    }
    
    @Override
    public void exec(String[] args) throws Exception {
        GetOpt opts = new GetOpt("[p]:[sslp]:", args);
        int port = opts.getInt("p", 9097);
        int sslPort = opts.getInt("sslp", 9460);
        
        QueuedThreadPool pool = new QueuedThreadPool();
        int maxThreads = IamServerConfig.getMaxThreads();
        pool.setMaxQueued(maxThreads);
        pool.setMaxThreads(maxThreads);
        pool.setMinThreads(IamServerConfig.getMinThreads());
        QueuedThreadPool sslPool = new QueuedThreadPool();
        sslPool.setMaxQueued(maxThreads);
        sslPool.setMaxThreads(maxThreads);
        sslPool.setMinThreads(IamServerConfig.getMinThreads());
        /* http://wiki.eclipse.org/Jetty/Tutorial/Embedding_Jetty */
        SelectChannelConnector connector0 = new SelectChannelConnector();
        connector0.setAcceptQueueSize(IamServerConfig.getAcceptQueueSize());// 增加backlog
        connector0.setThreadPool(pool);
        connector0.setPort(port);
        connector0.setMaxIdleTime(IamServerConfig.getSocketlIdleTimeout());
        connector0.setRequestHeaderSize(Consts.CONNECTOR_REQUEST_HEADER_SIZE);
        SslSelectChannelConnector ssl_connector = new SslSelectChannelConnector();
        ssl_connector.setPort(sslPort);
        ssl_connector.setMaxIdleTime(IamServerConfig.getSocketlIdleTimeout());
        ssl_connector.setRequestHeaderSize(Consts.CONNECTOR_REQUEST_HEADER_SIZE);
        ssl_connector.setAcceptQueueSize(IamServerConfig.getAcceptQueueSize());// 增加backlog
        ssl_connector.setThreadPool(sslPool);
        SslContextFactory cf = ssl_connector.getSslContextFactory();
        cf.setKeyStorePath(System.getenv("OOS_HOME") + IamServerConfig.getOosKeyStore());
        cf.setKeyStorePassword(IamServerConfig.getOosSslPasswd());
        Server server = new Server();
        server.setThreadPool(new QueuedThreadPool(IamServerConfig.getServerThreadPool())); // 增加最大线程数
        server.setConnectors(new Connector[] { connector0 });
        server.setHandler(new IAMHttpHandler());
        MBeanServer mBeanServer = ManagementFactory.getPlatformMBeanServer();
        MBeanContainer mBeanContainer = new MBeanContainer(mBeanServer);
        server.getContainer().addEventListener(mBeanContainer);
        mBeanContainer.start();
        try {
            server.start();
            LogUtils.startSuccess();
            server.join();
        } catch (Throwable e) {
            log.error(e.getMessage(), e);
            System.exit(-1);
        }
    }
}