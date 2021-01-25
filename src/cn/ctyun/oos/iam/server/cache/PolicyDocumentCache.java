package cn.ctyun.oos.iam.server.cache;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Timer;

import cn.ctyun.common.cache.Cache;
import cn.ctyun.oos.iam.accesscontroller.cache.IAMBatchUpdateCache;
import cn.ctyun.oos.iam.server.conf.IamServerConfig;
import cn.ctyun.oos.iam.server.service.AttachedPolicyService;

/**
 * 策略内容缓存
 * key：policyKey
 * value：policyDocument 策略内容
 * @author wangduo
 *
 */
public class PolicyDocumentCache extends IAMBatchUpdateCache {

    /** 批量获取数量 */
    private int batchGetSzie = 1000;
    
    public PolicyDocumentCache(Timer timer) {
        super(timer);
    }
    
    /**
     * 获取缓存中数据，没有数据使用load进行加载
     * @param policyKeys
     * @return
     * @throws IOException
     */
    public Map<String, String> getPolicyDocuments(Set<String> policyKeys) throws IOException {
        Map<String, String> resultMap = new HashMap<>();
        // 记录缓存中没有获取到的数据
        List<String> loadKeyList = new ArrayList<>();
        for (String policyKey : policyKeys) {
            // 如果使用缓存
            if (IamServerConfig.isUseCache()) {
                Cache cache = this.getContent(policyKey);
                if (cache == null || cache.value == null) {
                    loadKeyList.add(policyKey);
                } else {
                    // 将从缓存中获取到的值放入map中
                    resultMap.put(policyKey, cache.value.toString());
                }
            } else {
                // 不使用缓存全部从数据库加载
                loadKeyList.add(policyKey);
            }
        }
        // 加载没有从缓存中获取的数据
        List<Object> batchKeys = new ArrayList<>(batchGetSzie);
        for (int i = 0; i < loadKeyList.size(); i++) {
            String policyKey = loadKeyList.get(i);
            batchKeys.add(policyKey);
            // 如果遍历到批量的数量或者最后一条数据
            if ((i != 0  && i % batchGetSzie == 0) || i == loadKeyList.size() - 1) {
                // 批量获取数据
                Map<String, String> dataMap = load(batchKeys);
                for (Entry<String, String> entry : dataMap.entrySet()) {
                    if (entry.getValue() != null) {
                        // 将数据加入结果map中
                        resultMap.put(entry.getKey().toString(), entry.getValue().toString());
                        // 将数据加入缓存
                        this.putCache(entry.getKey(), new Cache(entry.getKey(), entry.getValue()));
                    }
                }
                // 初始化批量获取的列表
                batchKeys = new ArrayList<>(batchGetSzie);
            }
        }
        
        return resultMap;
    }
    
    
    @Override
    public Map<String, String> load(List<Object> keys) throws IOException {
        return AttachedPolicyService.getPolicyDoumentsMap(keys);
    }
}
