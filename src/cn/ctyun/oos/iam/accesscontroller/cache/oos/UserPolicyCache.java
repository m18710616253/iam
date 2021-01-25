package cn.ctyun.oos.iam.accesscontroller.cache.oos;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import cn.ctyun.common.conf.GlobalIamConfig;
import cn.ctyun.oos.hbase.IamChangeEventProcessor;
import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;
import cn.ctyun.oos.iam.accesscontroller.policy.PolicyParseException;
import cn.ctyun.oos.iam.server.service.AttachedPolicyService;
import cn.ctyun.oos.metadata.IamChangeEvent;
import cn.ctyun.oos.metadata.IamChangeEvent.ChangeType;

/**
 * 用户策略缓存
 * 
 * @author wangduo
 *
 */
public class UserPolicyCache {

    private static Log log = LogFactory.getLog(UserPolicyCache.class);

    /** 缓存更新timer */
    private static final Timer timer = new Timer();

    /** 用户缓存（包含用户策略关系列表及用户组关系列表数据） */
    public static WhiteListLocalCache<String, User> userCache = new WhiteListLocalCache<String, User>() {
        @Override
        protected int getSizeLimit() {
            return GlobalIamConfig.getUserCacheSize();
        }

        @Override
        protected User load(String key) throws IOException {
            User user = new User();
            user.policyKeys = AttachedPolicyService.getAttachedUserPolicyKeys(key);
            user.groupKeys = AttachedPolicyService.getUserGroupKeys(key);
            log.info("load user key : " + key + ", " + user);
            return user;
        }
    };

    /** 组缓存包含组策略关系列表数据 */
    public static WhiteListLocalCache<String, Group> groupCache = new WhiteListLocalCache<String, Group>() {
        @Override
        protected int getSizeLimit() {
            return GlobalIamConfig.getGroupCacheSize();
        }

        @Override
        protected Group load(String key) throws IOException {
            Group group = new Group();
            group.policyKeys = AttachedPolicyService.getAttachedGroupPolicyKeys(key);
            log.info("load group key : " + key + ", " + group);
            return group;
        }
    };

    /** 策略缓存（包含策略内容） */
    public static WhiteListLocalCache<String, Policy> policyCache = new WhiteListLocalCache<String, Policy>() {
        @Override
        protected int getSizeLimit() {
            return GlobalIamConfig.getPolicyCacheSize();
        }

        @Override
        protected Policy load(String key) throws IOException {
            Policy policy = new Policy();
            policy.policyDocument = AttachedPolicyService.getUserPolicyDoument(key);
            log.info("load policy key : " + key + ", " + policy);
            return policy;
        }
    };

    /** 缓存最后更新时间 */
    private static long lastExpireTime = 0;

    static {
        // 定时执行缓存更新
        timer.schedule(new TimerTask() {
            public void run() {
                try {
                    long now = System.currentTimeMillis();
                    // 没有到更新周期，不执行缓存更新
                    if (now - lastExpireTime < GlobalIamConfig.getCacheExpireTime()) {
                        return;
                    }
                    // 记录最后执行更新时间
                    lastExpireTime = now;
                    // 更新缓存
                    expire();
                } catch (Throwable t) {
                    log.error(t.getMessage(), t);
                }
            }
        }, 1000, 1000);

        // 添加更新处理
        IamChangeEventProcessor.addConsumer(event -> {
            try {
                updateCache(event);
            } catch (IOException e) {
                log.error("update cache failed, event :" + event);
            }
        });
    }

    /**
     * 通过事件更新缓存
     * @param event
     * @throws IOException
     */
    private static void updateCache(IamChangeEvent event) throws IOException {
     // 用户缓存更新
        if (event.type == ChangeType.USER) {
            userCache.reload(event.getKey());
        }
        // 组缓存更新
        if (event.type == ChangeType.GROUP) {
            groupCache.reload(event.getKey());
        }
        // 策略缓存更新
        if (event.type == ChangeType.POLICY) {
            policyCache.reload(event.getKey());
        }
    }
    
    /**
     * 获取修改事件，重新加载对应的缓存
     */
    private static void expire() {

        // 清除过期缓存
        userCache.expire();
        groupCache.expire();
        policyCache.expire();

    }

    /**
     * 获取用户策略
     * 
     * @param accountId
     * @param userName
     * @return
     * @throws IOException
     */
    public List<AccessPolicy> getPolicy(String accountId, String userName) throws IOException {
        String userKey = User.getUserKey(accountId, userName);
        User user = userCache.get(userKey);

        if (user == null) {
            log.error("accountId : " + accountId + ", userName : " + userName + ", the user is not exist in userCache.");
            return Collections.emptyList();
        }

        Set<String> policyKeys = new HashSet<String>();
        // 将用户策略key添加到策略key列表中
        if (user.policyKeys != null) {
            policyKeys.addAll(user.policyKeys);
        }
        // 将用户组的策略key添加到策略key列表中
        if (user.groupKeys != null) {
            for (String groupKey : user.groupKeys) {
                Group group = groupCache.get(groupKey);
                if (group == null) {
                    log.error("accountId : " + accountId + ", userName : " + userName + ", groupKey : " + groupKey + ", the group is not exist in groupCache.");
                    continue;
                }
                if (group.policyKeys != null) {
                    policyKeys.addAll(group.policyKeys);
                }
            }
        }
        // 获取策略列表
        List<AccessPolicy> accessPolicies = new ArrayList<AccessPolicy>();
        for (String policyKey : policyKeys) {
            Policy policy = policyCache.get(policyKey);
            if (policy == null) {
                log.error("accountId : " + accountId + ", userName : " + userName + ", policyKey : " + policyKey + ", the policy is not exist in policyCache.");
                continue;
            }
            try {
                accessPolicies.add(AccessPolicy.fromJson(policy.policyDocument));
            } catch (PolicyParseException e) {
                log.error("policyDocument parse failed, policyKey : " + policyKey, e);
            }
        }
        return accessPolicies;
    }

}
