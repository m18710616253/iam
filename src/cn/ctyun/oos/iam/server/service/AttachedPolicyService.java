package cn.ctyun.oos.iam.server.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.entity.GroupPolicy;
import cn.ctyun.oos.iam.server.entity.Policy;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.entity.UserGroup;
import cn.ctyun.oos.iam.server.entity.UserPolicy;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.hbase.Qualifier;

/**
 * 获取附加策略逻辑
 * @author wangduo
 *
 */
public class AttachedPolicyService {

    private static final Log log = LogFactory.getLog(AttachedPolicyService.class);
    
    /**
     * 获取附加在用户上的策略的key列表
     * @param user
     * @return
     * @throws IOException
     */
    public static List<String> getAttachedUserPolicyKeys(String userKey) throws IOException {
        
        User user = new User();
        user.parseUserKey(userKey);
        
        UserPolicy uPolicy = new UserPolicy();
        uPolicy.accountId = user.accountId;
        uPolicy.userName = user.userName;
        // 用户和策略关系的rowkey前缀
        String userPolicyPrefix = uPolicy.getUserPolicyPrefix();
        Scan scan = new Scan();
        scan.setStartRow(Bytes.toBytes(userPolicyPrefix + Character.MIN_VALUE));
        scan.setStopRow(Bytes.toBytes(userPolicyPrefix + Character.MAX_VALUE));
        
        List<String> policyKeys = new ArrayList<>();
        // 用户和策略关系的rowkey列表
        List<UserPolicy> userPolicies = HBaseUtils.listResult(scan, UserPolicy.class);
        // 获取策略列表
        for (UserPolicy userPolicy : userPolicies) {
            policyKeys.add(userPolicy.getPolicy().getPolicyKey());
        }
        
        if (log.isDebugEnabled()) {
            log.debug("user : " + userKey +", getAttachedUserPolicyKeys : " + policyKeys);
        }
        
        return policyKeys;
    }
    
    /**
     * 获取用户的组的key列表
     * @param userKey
     * @return
     * @throws IOException 
     */
    public static List<String> getUserGroupKeys(String userKey) throws IOException {

        User user = new User();
        user.parseUserKey(userKey);
        UserGroup uGroup = new UserGroup();
        uGroup.accountId = user.accountId;
        uGroup.userName = user.userName;
        // 用户和组关系的rowkey前缀
        String userGroupPrefix = uGroup.getUserPrefix();
        
        Scan scan = new Scan();
        scan.setStartRow(Bytes.toBytes(userGroupPrefix + Character.MIN_VALUE));
        scan.setStopRow(Bytes.toBytes(userGroupPrefix + Character.MAX_VALUE));
        
        List<String> groupKeys = new ArrayList<>();
        // 用户和组关系的rowkey列表
        List<UserGroup> userGroups = HBaseUtils.listResult(scan, UserGroup.class);
        // 获取组列表
        for (UserGroup userGroup : userGroups) {
            groupKeys.add(userGroup.getGroup().getGroupKey());
        }
        return groupKeys;
    }
    
    /**
     * 获取附加在组上的策略的key列表
     * @param user
     * @return
     * @throws IOException
     */
    public static List<String> getAttachedGroupPolicyKeys(String groupKey) throws IOException {
        
        Group group = new Group();
        group.parseGroupKey(groupKey);
        // 组策略关系
        GroupPolicy gPolicy = new GroupPolicy();
        gPolicy.accountId = group.accountId;
        gPolicy.groupName = group.groupName;
        // 组和策略关系的rowkey前缀
        String groupPolicyPrefix = gPolicy.getGroupPolicyPrefix();
        Scan scan = new Scan();
        scan.setStartRow(Bytes.toBytes(groupPolicyPrefix + Character.MIN_VALUE));
        scan.setStopRow(Bytes.toBytes(groupPolicyPrefix + Character.MAX_VALUE));
        
        List<String> policyKeys = new ArrayList<>();
        // 组和策略关系的rowkey列表
        List<GroupPolicy> groupPolicies = HBaseUtils.listResult(scan, GroupPolicy.class);
        // 获取策略列表
        for (GroupPolicy groupPolicy : groupPolicies) {
            // 解析组和策略关系的rowkey
            policyKeys.add(groupPolicy.getPolicy().getPolicyKey());
        }
        return policyKeys;
    }
    
    /**
     * 通过策略key列表批量获取策略内容
     * @param keys
     * @return key: 策略的key, value: 策略内容
     * @throws IOException
     */
    public static Map<String, String> getPolicyDoumentsMap(List<Object> keys) throws IOException {
        // 策略rowkey列表
        List<byte[]> policyRowKeys = new ArrayList<>();
        for (Object policyRowKey : keys) {
            policyRowKeys.add(Bytes.toBytes(policyRowKey.toString()));
        }
        Map<String, String> policyDocumentMap = HBaseUtils.get(policyRowKeys, Policy.class, 
                Bytes.toBytes(Qualifier.DEFAULT_FAMILY), Bytes.toBytes(Policy.QUALIFIER_DOCUMENT));
        return policyDocumentMap;
    }
    
    /**
     * 获取策略列表对应的策略内容
     * @param policyKeys
     * @return
     * @throws IOException
     */
    public static List<String> getUserPolicyDouments(Set<String> policyKeys) throws IOException {
        // 策略rowkey列表
        List<byte[]> policyRowKeys = new ArrayList<>();
        for (String policyKey : policyKeys) {
            policyRowKeys.add(Bytes.toBytes(policyKey.toString()));
        }
        Map<String, String> policyDocumentMap = HBaseUtils.get(policyRowKeys, Policy.class, 
                Bytes.toBytes(Qualifier.DEFAULT_FAMILY), Bytes.toBytes(Policy.QUALIFIER_DOCUMENT));
        return new ArrayList<>(policyDocumentMap.values());
    }
    
    /**
     * 获取指定policykey的策略内容
     * @param policyKey
     * @return
     * @throws IOException
     */
    public static String getUserPolicyDoument(String policyKey) throws IOException {
        byte[] bytes = HBaseUtils.get(policyKey.getBytes(), Policy.class, 
                Bytes.toBytes(Qualifier.DEFAULT_FAMILY), Bytes.toBytes(Policy.QUALIFIER_DOCUMENT));
        if (bytes == null) {
            return null;
        }
        return Bytes.toString(bytes);
    }
    
    
    /**
     * 获取指定用户的策略列表
     * @param user
     * @return key: userKey, value: 用户的策略列表
     * @throws IOException
     */
    public static List<String> getUserPolicyDocuments(String userKey) throws IOException {
        
        // 用户的policyKey列表的map
        Map<String, Set<String>> usersPolicyKeys = new HashMap<>();
        // 需要获取数据的所有的policyKey
        Set<String> policyKeys = new HashSet<>();
        
        Set<String> userPolicyKeys = new HashSet<>();
        usersPolicyKeys.put(userKey, userPolicyKeys);
        // 获取附加在用户的策略key
        List<String> attachUserPolicyKeys = getAttachedUserPolicyKeys(userKey);
        userPolicyKeys.addAll(attachUserPolicyKeys);
        policyKeys.addAll(attachUserPolicyKeys);
        // 获取用户的组的key列表
        List<String> groupKeys = getUserGroupKeys(userKey);
        for (String groupKey : groupKeys) {
            // 获取附加到组上的策略key列表
            List<String> attachGroupPolicyKeys = getAttachedGroupPolicyKeys(groupKey);
            userPolicyKeys.addAll(attachGroupPolicyKeys);
            policyKeys.addAll(attachGroupPolicyKeys);
        }
        
        return getUserPolicyDouments(policyKeys);
    }
}
