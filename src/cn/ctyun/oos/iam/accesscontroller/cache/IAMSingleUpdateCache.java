package cn.ctyun.oos.iam.accesscontroller.cache;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Timer;

import cn.ctyun.common.cache.Cache;
import cn.ctyun.oos.iam.server.conf.IamServerConfig;

/**
 * IAM单条定时更新缓存
 * @author wangduo
 *
 */
public abstract class IAMSingleUpdateCache extends IAMLocalCache {

    public IAMSingleUpdateCache(Timer timer) {
        super(timer);
    }
    
    /**
     * 对需要更新的缓存数据进行更新
     * @param validateEntries 需要更新的缓存列表
     * @return 返回没有获取到数据（被删除）的key的列表
     * @throws IOException 
     */
    @Override
    public List<Object> update(List<Entry<Object, Cache>> validateEntries) throws IOException {
        // 失效key列表
        List<Object> invalidateKeys = new ArrayList<>();
        // 待更新的缓存列表
        for (Entry<Object, Cache> entry : validateEntries) {
            // 获取数据
            Object newValue = load(entry.getKey());
            Object key = entry.getKey();
            Cache cache = entry.getValue();
            // 如果key没有加载到数据，记录到失效key列表中
            if (newValue == null) {
                invalidateKeys.add(key);
            } else {
                // 更新缓存数据
                cache.value = newValue;
                // 设置更新时间
                cache.lastUpdate.set(System.currentTimeMillis());
            }
        }
        return invalidateKeys;
    }
    
    /**
     * 获取缓存中数据，没有数据使用load进行加载，加载后放入缓存
     * @param userKey
     * @return
     * @throws IOException
     */
    public Object get(String key) throws IOException {
        // 如果使用缓存，从缓存中获取数据
        if (IamServerConfig.isUseCache()) {
            Cache cache = this.getContent(key);
            if (cache != null) {
                return cache.value;
            }
            // 没有获取到缓存，加载数据并设置到缓存
            Object value = load(key);
            this.putCache(key, new Cache(key, value));
            return value;
        } else {
            // 不使用缓存从数据库加载
            return load(key);
        }
    }
    
    /**
     * 加载key对应的数据
     * 需要子类进行实现，用于缓存的定时更新，加载数据
     * @param key
     * @return map key为keys列表中的key，value为key对应的加载的数据
     * @throws IOException 
     */
    public abstract Object load(Object key) throws IOException;
}
