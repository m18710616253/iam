package cn.ctyun.oos.iam.server.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Timer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import cn.ctyun.oos.iam.accesscontroller.cache.DataLoader;
import cn.ctyun.oos.iam.accesscontroller.cache.SemaphoreDataLoader;
import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;
import cn.ctyun.oos.iam.accesscontroller.service.PolicyService;
import cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache;
import cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache;
import cn.ctyun.oos.iam.server.cache.PolicyDocumentCache;
import cn.ctyun.oos.iam.server.cache.UserGroupKeysCache;
import cn.ctyun.oos.iam.server.entity.User;

/**
 * IAM Server 用户策略
 * 
 * @author wangduo
 *
 */
public class IAMPolicyService implements PolicyService {
    
    private static final Log log = LogFactory.getLog(IAMPolicyService.class);

    /** 缓存更新定时器 */
    private static final Timer timer = new Timer();
    
    /** 用户附加的策略key的缓存 */
    public static final AttachUserPolicyKeysCache attachUserPolicyKeysCache = new AttachUserPolicyKeysCache(timer);
    /** 用户的组的key缓存 */
    public static final UserGroupKeysCache userGroupKeysCache = new UserGroupKeysCache(timer);
    /** 组附加的策略key的缓存 */
    public static final AttachGroupPolicyKeysCache attachGroupPolicyKeysCache = new AttachGroupPolicyKeysCache(timer);
    /** 策略内容缓存 */
    public static final PolicyDocumentCache policyDocumentCache = new PolicyDocumentCache(timer);
    
    /**
     * 单用户的策略列表加载工具
     * 防止过多的线程同时获取同一个用户的策略，并发访问数据库，数据由少数线程加载 
     */
    private DataLoader<List<String>> userPoliciesLoader = new SemaphoreDataLoader<List<String>>() {
        @Override
        public boolean contains(String key) {
            return attachUserPolicyKeysCache.getContent(key) != null;
        }
        @Override
        public List<String> loadAndSet(String key) throws IOException {
            return getUserPolicyDouments(key);
        }
        @Override
        public List<String> fromCache(String key) throws IOException {
            return getUserPolicyDouments(key);
        }
    };
    
    
    /**
     * 获取IAM用户的所有策略
     * @throws IOException 
     */
    @Override
    public List<AccessPolicy> getUserPolicies(String accountId, String userName) throws IOException {
       
        User user = new User();
        user.accountId = accountId;
        user.userName = userName;
        // 循环解析policy
        List<AccessPolicy> policies = new ArrayList<>();
        List<String> policyDocuments = getUserPoliciesByLoader(user.getUserKey());
        for (String policyDocument : policyDocuments) {
            try {
                AccessPolicy policy = AccessPolicy.fromJson(policyDocument);
                policies.add(policy);
            } catch (Exception e) {
                // 之前保存的用户策略格式不正确，此处会报错
                // 程序正常的情况下不会报该错误 
                // TODO 考虑如何处理异常 500 还是 400 还是忽略
                log.error("Parse policy json failed. policyDocument:" + policyDocument, e);
            }
        }
        return policies;
    }
    
    /**
     * 获取单个用户的策略内容列表
     * @param userKey
     * @return
     * @throws IOException
     */
    public List<String> getUserPoliciesByLoader(String userKey) throws IOException {
        return userPoliciesLoader.get(userKey);
    }
    
    /**
     * 获取用户的策略列表
     * @param userKey
     * @return
     * @throws IOException
     */
    private List<String> getUserPolicyDouments(String userKey) throws IOException {
        Map<String, List<String>> usersPolicyDocument = getUsersPolicyDocuments(Arrays.asList(userKey));
        List<String> documents = usersPolicyDocument.get(userKey);
        if (documents == null) {
            return Collections.emptyList();
        }
        return documents;
    }
    
    /**
     * 获取指定用户列表中每个用户的策略列表
     * @param user
     * @return key: userKey, value: 用户的策略列表
     * @throws IOException
     */
    public Map<String, List<String>> getUsersPolicyDocuments(List<String> userKeys) throws IOException {
        
        // 用户的policyKey列表的map
        Map<String, Set<String>> usersPolicyKeys = new HashMap<>();
        // 需要获取数据的所有的policyKey
        Set<String> policyKeys = new HashSet<>();
        
        for (String userKey : userKeys) {
            Set<String> userPolicyKeys = new HashSet<>();
            usersPolicyKeys.put(userKey, userPolicyKeys);
            // 获取附加在用户的策略key
            List<String> attachUserPolicyKeys = attachUserPolicyKeysCache.getPolicyKeys(userKey);
            
            if (log.isDebugEnabled()) {
                log.debug("user : " + userKey +", attachUserPolicyKeys : " +  attachUserPolicyKeys);
            }
            
            userPolicyKeys.addAll(attachUserPolicyKeys);
            policyKeys.addAll(attachUserPolicyKeys);
            // 获取用户的组的key列表
            List<String> groupKeys = userGroupKeysCache.getGroupKeys(userKey);
            
            if (log.isDebugEnabled()) {
                log.debug("user : " + userKey +", userGroupKeys : " +  groupKeys);
            }

            for (String groupKey : groupKeys) {
                // 获取附加到组上的策略key列表
                List<String> attachGroupPolicyKeys = attachGroupPolicyKeysCache.getPolicyKeys(groupKey);
                userPolicyKeys.addAll(attachGroupPolicyKeys);
                policyKeys.addAll(attachGroupPolicyKeys);
            }
            
            if (log.isDebugEnabled()) {
                log.debug("user : " + userKey +", policyKeys : " + policyKeys);
            }
            
        }
        // 获取所有的策略内容
        Map<String, String> policyDocumentMap = policyDocumentCache.getPolicyDocuments(policyKeys);
        // 用户策略内容列表map
        Map<String, List<String>> usersPolicyDocumentMap = new HashMap<>();
        // 遍历用户及策略keySet
        for (Entry<String, Set<String>> userPolicySetEntry : usersPolicyKeys.entrySet()) {
            // 用户策略列表
            List<String> policyDocuments = new ArrayList<>();
            String userKey = userPolicySetEntry.getKey();
            usersPolicyDocumentMap.put(userKey, policyDocuments);
            // 遍历策略列表
            for (String policyKey : userPolicySetEntry.getValue()) {
                // 获取策略
                String document = policyDocumentMap.get(policyKey);
                if (document != null) {
                    policyDocuments.add(document);
                }
            }
            
            if (log.isDebugEnabled()) {
                log.debug("user : " + userKey +", policyDocuments : " + policyDocuments);
            }
            
        }
        
        return usersPolicyDocumentMap;
    }
    
}
