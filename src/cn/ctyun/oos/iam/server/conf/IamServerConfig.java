package cn.ctyun.oos.iam.server.conf;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;

import cn.ctyun.common.Consts;
import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.common.dsync.DListener;
import cn.ctyun.common.dsync.DSyncService;
import cn.ctyun.common.dsync.DValue;
import cn.ctyun.common.node.OosZKNode;
import common.util.JsonUtils.UnJsonable;

/**
 * IAM服务配置
 */
public class IamServerConfig {
    private static int maxThreads = 10000;
    private static int minThreads = 100;
    private static int socketlIdleTimeout = 30 * 1000;
    private static int acceptQueueSize = 4 * 1024;
    private static String oosSslPasswd = "cloudct-jetty";
    private static String oosKeyStore = "/conf/ssl/jettyyunjisuan.jks";
    private static int serverThreadPool = 10000;
    /**策略缓存更新时间ms */
    private static int cacheTimeout = 30000;
    /** 是否使用策略缓存 */
    private static boolean useCache = false;
    
    private static final Log log = LogFactory.getLog(IamServerConfig.class);
    private static DSyncService dsync;
    static {
        try {
            dsync = new DSyncService(GlobalHHZConfig.getQuorumServers(),
                    GlobalHHZConfig.getSessionTimeout());
        } catch (IOException e) {
            throw new RuntimeException("Create DSyncService failed.", e);
        }
    }
    private static DValue value;
    static {
        value = dsync.listen(OosZKNode.iamServerConfigPath, new DListener() {
            public void onChanged() {
                try {
                    synchronized (IamServerConfig.class) {
                        byte[] data = value.get();
                        deserialize(IamServerConfig.class, data);
                    }
                } catch (Throwable e) {
                    log.error(e.getMessage(), e);
                }
            }
        });
        try {
            synchronized (IamServerConfig.class) {
                byte[] data = value.get();
                deserialize(IamServerConfig.class, data);
            }
        } catch (Throwable e) {
            log.error(e.getMessage(), e);
        }
    }

    private static void deserialize(Class<?> clazz, byte[] data) {
        if (data == null)
            return;
        try {
            String v = new String(data, 0, data.length, Consts.CS_UTF8);
            JSONObject jo = new JSONObject(v);
            Field[] fields = clazz.getDeclaredFields();
            for (Field field : fields) {
                field.setAccessible(true);
                int m = field.getModifiers();
                if (Modifier.isFinal(m) || field.isAnnotationPresent(UnJsonable.class))
                    continue;
                if (jo.has(field.getName())) {
                    if (field.getType().isArray()) {
                        String[] tmp = jo.get(field.getName()).toString().split(",");
                        field.set(clazz, tmp);
                    } else
                        field.set(clazz, jo.get(field.getName()));
                }
            }
            log.info("The data of IamConfig has changed.");
            log.info("Now the data of IamConfig is:" + System.getProperty("line.separator")
                    + jo.toString());
        } catch (Exception e) {
            throw new RuntimeException("Deserialize Error", e);
        }
    }

    public static int getMaxThreads() {
        return maxThreads;
    }

    public static int getMinThreads() {
        return minThreads;
    }

    public static int getSocketlIdleTimeout() {
        return socketlIdleTimeout;
    }

    public static int getAcceptQueueSize() {
        return acceptQueueSize;
    }

    public static String getOosSslPasswd() {
        return oosSslPasswd;
    }

    public static String getOosKeyStore() {
        return oosKeyStore;
    }

    public static int getServerThreadPool() {
        return serverThreadPool;
    }

    public static int getCacheTimeout() {
        return cacheTimeout;
    }

    public static boolean isUseCache() {
        return useCache;
    }
    
}
