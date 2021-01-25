package cn.ctyun.oos.iam.accesscontroller.cache;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Timer;

import cn.ctyun.common.cache.Cache;

/**
 * IAM批量更新缓存
 * @author wangduo
 *
 */
public abstract class IAMBatchUpdateCache extends IAMLocalCache {

    /** 批量更新数量 */
    private int batchUpdateSzie = 1000;
    
    public IAMBatchUpdateCache(Timer timer) {
        super(timer);
    }
    
    /**
     * 对需要更新的缓存数据进行批量更新
     * @param validateEntries 需要更新的缓存列表
     * @return 返回没有获取到数据（被删除）的key的列表
     * @throws IOException 
     */
    @Override
    public List<Object> update(List<Entry<Object, Cache>> validateEntries) throws IOException {
        // 失效key列表
        List<Object> invalidateKeys = new ArrayList<>();
        // 批量获取的key的列表
        List<Object> batchKeys = new ArrayList<>(batchUpdateSzie);
        // 待更新的缓存列表
        List<Entry<Object, Cache>> updateEntries = new ArrayList<>(batchUpdateSzie);
        for (int i = 0; i < validateEntries.size(); i++) {
            Entry<Object, Cache> entry = validateEntries.get(i);
            batchKeys.add(entry.getKey());
            updateEntries.add(entry);
            // 如果遍历到批量的数量或者最后一条数据
            if ((i != 0  && i % batchUpdateSzie == 0) || i == validateEntries.size() - 1) {
                // 批量获取数据
                Map<String, String> dataMap = load(batchKeys);
                for (Entry<Object, Cache> updateEntry : updateEntries) {
                    Object key = updateEntry.getKey();
                    Cache cache = updateEntry.getValue();
                    Object newValue = dataMap.get(key);
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
                // 初始化批量获取的列表
                batchKeys = new ArrayList<>(batchUpdateSzie);
                updateEntries = new ArrayList<>(batchUpdateSzie);
            }
        }
        return invalidateKeys;
    }
    
    
    /**
     * 加载key列表对应的数据
     * 需要子类进行实现，用于缓存的定时更新，批量加载数据
     * @param key
     * @return map key为keys列表中的key，value为key对应的加载的数据
     * @throws IOException 
     */
    public abstract Map<String, String> load(List<Object> keys) throws IOException;
}
