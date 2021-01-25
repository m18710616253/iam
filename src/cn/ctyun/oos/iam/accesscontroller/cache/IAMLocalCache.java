package cn.ctyun.oos.iam.accesscontroller.cache;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import cn.ctyun.common.cache.Cache;
import cn.ctyun.common.cache.LocalCache;
import cn.ctyun.oos.iam.server.conf.IamServerConfig;

/**
 * IAM本地缓存
 * @author wangduo
 *
 */
public abstract class IAMLocalCache extends LocalCache {

    private static Log log = LogFactory.getLog(IAMLocalCache.class);
    
    public IAMLocalCache(Timer timer) {
        super();
        // 缓存定时更新任务
        timer.schedule(new TimerTask() {
            public void run() {
                try {
                    LinkedList<Object> invalidateKeys = new LinkedList<>();
                    LinkedList<Entry<Object, Cache>> validateEntries = new LinkedList<>();
                    synchronized(this) {
                        Set<Entry<Object, Cache>> entrySet = cacheMap.entrySet();
                        for (Entry<Object, Cache> entry : entrySet) {
                            Object key = entry.getKey();
                            Cache cache = entry.getValue();
                            // 最后访问时间
                            long lastVisit = cache.lastVisit.get();
                            // 最后更新时间
                            long lastUpdate = cache.lastUpdate.get();
                            // 通过最后访问时间 lastVisit 判断数据是否过期
                            if ((System.currentTimeMillis() - lastVisit) > IamServerConfig.getCacheTimeout() * 3) {
                                // 记录过期的数据
                                invalidateKeys.add(key);
                                continue;
                            }
                            // 通过最后更新时间 lastUpdate 判断数据是否需要更新
                            if (System.currentTimeMillis() - lastUpdate > IamServerConfig.getCacheTimeout()) {
                                // 记录需要更新的数据
                                validateEntries.add(entry);
                            }
                        }
                    }
                    // 批量更新数据
                    List<Object> batchInvalidateKeys = update(validateEntries);
                    // 如果获取不到该数据，加入清除列表
                    invalidateKeys.addAll(batchInvalidateKeys);
                    // 清除过期数据
                    for (Object k : invalidateKeys) {
                        invalidate(String.valueOf(k));
                    }
                } catch (Throwable t) {
                    log.error(t.getMessage(), t);
                }
            }
        }, IamServerConfig.getCacheTimeout(), IamServerConfig.getCacheTimeout());    
    }
    
    /**
     * 对需要更新的缓存数据进行批量更新
     * @param validateEntries 需要更新的缓存列表
     * @return 返回没有获取到数据（被删除）的key的列表
     * @throws IOException 
     */
    public abstract List<Object> update(List<Entry<Object, Cache>> validateEntries) throws IOException;
    
}
