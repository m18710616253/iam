package cn.ctyun.oos.iam.test.oosaccesscontrol;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.ctyun.common.BaseException;
import cn.ctyun.common.cache.Cache;
import cn.ctyun.common.conf.GlobalIamConfig;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.cache.oos.CacheValue;
import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;
import cn.ctyun.oos.iam.accesscontroller.policy.Principal;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.service.IAMPolicyClient;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.metadata.UserToTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta.VSNTagType;
import common.tuple.Pair;

/*
 *
 *更改配置globalIamConfig
 *"cacheTimeOut":10000,
    "useCache": true,
    "userCacheSize": 5,
    "groupCacheSize": 5,
    "policyCacheSize": 5,
    "accessKeyCacheSize": 5,
    "cacheExpireTime":30000
 *
 *修改
 *1.UserPolicyCache.java的getpolicy方法最后返回accessPolicies之前加入以下代码
 *for (AccessPolicy policy : accessPolicies) {
            System.out.println("-------------------real cache :Key="+"accountId : " + accountId + ", userName : " + userName+",policy="+policy.jsonString);
        }
        System.out.println("-----------------------cache size="+accessPolicies.size());

 *2.在WhiteListLocalCache.java中添加以下几处打印
 *public WhiteListLocalCache() {
        cacheMap = new LinkedHashMap<K, CacheValue<V>>() {
            
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(java.util.Map.Entry<K, CacheValue<V>> eldest) {
                Iterator<K> iterator = cacheMap.keySet().iterator();
                while (size() - getSizeLimit() > 0 && iterator.hasNext()) {
                    Object key = iterator.next();
                    // 不清除白名单中的缓存
                    if (inWhiteList(key.toString())) {
                        continue;
                    }
                    cacheMap.remove(key);
                    System.out.println("------------------remove cache:key="+key);
                    log.info(this.getClass().getSimpleName() + " size larger than " + getSizeLimit() + ", remove key " + key);
                }
                return false;
            }
        };
        init();
    }
    
    private synchronized CacheValue<V> put(K key, V value) {
        CacheValue<V> cacheValue = new CacheValue<>(key, value);
        cacheMap.put(key, cacheValue);
        System.out.println("-----------size="+cacheMap.size());
        return cacheValue;
    }
    
    public V get(K key) throws IOException {
        // 如果配置了不使用缓存，直接加载数据
        if (!GlobalIamConfig.isUseCache()) {
            return load(key);
        }
        CacheValue<V> cache = getCacheValue(key);
        if(cache == null) {
            Object lock = keyLocks.computeIfAbsent(key, k -> new Object());
            try {
                // 防止并发访问数据库加载数据
                synchronized (lock) {
                    cache = getCacheValue(key);
                    if (cache == null) {
                        System.out.println("------------------not in cache:key="+key);
                        V value = load(key);
                        cache = put(key, value);
                    }
                }
            } finally {
                keyLocks.remove(lock);
            }
        }else {
            System.out.println("------------------in cache:key="+key);
        }
        cache.lastVisit.set(System.currentTimeMillis());
        return cache.value;
    }
    
    public synchronized CacheValue<V> getCacheValue(K key) {
        System.out.println("-----------size="+cacheMap.size());
        return cacheMap.get(key);
    }
    
    public synchronized void expire() {
        List<K> removeKeys = new ArrayList<>();
        for (Entry<K, CacheValue<V>> entry : cacheMap.entrySet()) {
            long lastVisitTime = entry.getValue().lastVisit.get();
            // 不在白名单且过期，清除缓存
            if (!inWhiteList(entry.getKey().toString()) && ((System.currentTimeMillis() - lastVisitTime) > GlobalIamConfig.getCacheExpireTime())) {
                // 记录需要清理的key
                removeKeys.add(entry.getKey());
            }
        }
        // 对过期的缓存进行清理
        for (K key : removeKeys) {
            cacheMap.remove(key);
            System.out.println("------------------remove expire cache:key="+key);
        }
        if (!removeKeys.isEmpty()) {
            log.info("Remove expired keys : " + removeKeys);
        }
        
    }
 *
 *
 */
public class OOSPolicyCacheTest {
    
    public static final String bucketName1="yx-bucket-1";
    public static final String bucketName2="yx-bucket-2";
    
    private static String ownerName = "root_user1@test.com";
    public static final String accessKey="userak11111111111";
    public static final String secretKey="usersk11111111111";
    
    private static String ownerName2 = "root_user2@test.com";
    public static final String accessKey2="userak2";
    public static final String secretKey2="usersk2";
    
    public static final String user1Name="test_1";
    public static final String user2Name="test_2";
    public static final String user3Name="test_3";
    public static final String user4Name="test_4";
    public static final String user5Name="test_5";
    public static final String user6Name="test_6";

    public static final String user1accessKey="user1ak1111111111";
    public static final String user1secretKey="user1sk1111111111";
    public static final String user2accessKey="user2ak";
    public static final String user2secretKey="user2sk";
    public static final String user3accessKey="user3ak";
    public static final String user3secretKey="user3sk";
    public static final String user4accessKey="user4ak";
    public static final String user4secretKey="user4sk";
    public static final String user5accessKey="user5ak";
    public static final String user5secretKey="user5sk";
    public static final String user6accessKey="user6ak";
    public static final String user6secretKey="user6sk";
    
    public static final String accountId1="3fdmxmc3pqvmp";
    public static final String accountId2="098kw0mm2j4p8";
    
    public static final String policyName1="alloosPolicy";
    public static final String policyName2="alloosBucketPolicy";
    public static final String policyName3="alloosObjectPolicy";
    public static final String policyName4="DenyDeleteObject";
    public static final String policyName5="DenyPutObject";
    public static final String policyName6="DenyBucket";
    
    
    public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static OwnerMeta owner2 = new OwnerMeta(ownerName2);
    public static MetaClient metaClient = MetaClient.getGlobalClient();

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);
        CreateUserAndPolicy();
    }

    @Before
    public void setUp() throws Exception { 

     
    }
    
    @Test
    public void clean() {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable); 
    }
    
    public static void CreateUserAndPolicy() throws Exception {
     // 创建根用户1
        owner.email=ownerName;
        owner.setPwd("123456");
        owner.maxAKNum=10;
        owner.displayName="测试根用户";
        owner.bucketCeilingNum=10;
        metaClient.ownerInsertForTest(owner);
        AkSkMeta aksk=new AkSkMeta(owner.getId());
        aksk.accessKey=accessKey;
        aksk.setSecretKey(secretKey);
        aksk.isPrimary=1;
        metaClient.akskInsert(aksk);
        
        // 创建根用户2
        owner2.email=ownerName2;
        owner2.setPwd("123456");
        owner2.maxAKNum=10;
        owner2.displayName="测试根用户";
        owner2.bucketCeilingNum=10;
        metaClient.ownerInsertForTest(owner2);
        AkSkMeta aksk2=new AkSkMeta(owner2.getId());
        aksk2.accessKey=accessKey2;
        aksk2.setSecretKey(secretKey2);
        aksk2.isPrimary=1;
        metaClient.akskInsert(aksk2);
        
        // 创建user1
        String userName1=user1Name;
        User user1=new User();
        user1.accountId=accountId1;
        user1.userName=userName1;
        user1.userId="userid1";
        user1.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user1);
            assertTrue(success);
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        AkSkMeta useraksk1 = new AkSkMeta(owner.getId());
        useraksk1.isRoot = 0;
        useraksk1.userId = user1.userId;
        useraksk1.userName = userName1;
        useraksk1.accessKey=user1accessKey;
        useraksk1.setSecretKey(user1secretKey);
        metaClient.akskInsert(useraksk1);
        user1.accessKeys = new ArrayList<>();
        user1.userName=userName1;
        user1.accessKeys.add(useraksk1.accessKey);
        HBaseUtils.put(user1);
        
        // 创建user2
        String userName2=user2Name;
        User user2=new User();
        user2.accountId=accountId1;
        user2.userName=userName2;
        user2.userId="userid2";
        user2.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user2);
            assertTrue(success);
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        AkSkMeta useraksk2 = new AkSkMeta(owner.getId());
        useraksk2.isRoot = 0;
        useraksk2.userId = user2.userId;
        useraksk2.userName = userName2;
        useraksk2.accessKey=user2accessKey;
        useraksk2.setSecretKey(user2secretKey);
        metaClient.akskInsert(useraksk2);
        user2.accessKeys = new ArrayList<>();
        user2.userName=userName2;
        user2.accessKeys.add(useraksk2.accessKey);
        HBaseUtils.put(user2);
        
        // 创建user3
        String userName3=user3Name;
        User user3=new User();
        user3.accountId=accountId2;
        user3.userName=userName3;
        user3.userId="userid3";
        user3.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user3);
            assertTrue(success);
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        AkSkMeta useraksk3 = new AkSkMeta(owner2.getId());
        useraksk3.isRoot = 0;
        useraksk3.userId = user3.userId;
        useraksk3.userName = userName3;
        useraksk3.accessKey=user3accessKey;
        useraksk3.setSecretKey(user3secretKey);
        metaClient.akskInsert(useraksk3);
        user3.accessKeys = new ArrayList<>();
        user3.userName=userName3;
        user3.accessKeys.add(useraksk3.accessKey);
        HBaseUtils.put(user3);
        
        // 创建user4
        String userName4=user4Name;
        User user4=new User();
        user4.accountId=accountId2;
        user4.userName=userName4;
        user4.userId="userid4";
        user4.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user4);
            assertTrue(success);
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        AkSkMeta useraksk4 = new AkSkMeta(owner2.getId());
        useraksk4.isRoot = 0;
        useraksk4.userId = user4.userId;
        useraksk4.userName = userName4;
        useraksk4.accessKey=user4accessKey;
        useraksk4.setSecretKey(user4secretKey);
        metaClient.akskInsert(useraksk4);
        user4.accessKeys = new ArrayList<>();
        user4.userName=userName4;
        user4.accessKeys.add(useraksk4.accessKey);
        HBaseUtils.put(user4);
        
        // 创建user5
        String userName5=user5Name;
        User user5=new User();
        user5.accountId=accountId2;
        user5.userName=userName5;
        user5.userId="userid5";
        user5.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user5);
            assertTrue(success);
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        AkSkMeta useraksk5 = new AkSkMeta(owner2.getId());
        useraksk5.isRoot = 0;
        useraksk5.userId = user5.userId;
        useraksk5.userName = userName5;
        useraksk5.accessKey=user5accessKey;
        useraksk5.setSecretKey(user5secretKey);
        metaClient.akskInsert(useraksk5);
        user5.accessKeys = new ArrayList<>();
        user5.userName=userName5;
        user5.accessKeys.add(useraksk5.accessKey);
        HBaseUtils.put(user5);
        
        // 创建user6
        String userName6=user6Name;
        User user6=new User();
        user6.accountId=accountId2;
        user6.userName=userName6;
        user6.userId="userid6";
        user6.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user6);
            assertTrue(success);
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        AkSkMeta useraksk6 = new AkSkMeta(owner2.getId());
        useraksk6.isRoot = 0;
        useraksk6.userId = user6.userId;
        useraksk6.userName = userName6;
        useraksk6.accessKey=user6accessKey;
        useraksk6.setSecretKey(user6secretKey);
        metaClient.akskInsert(useraksk6);
        user6.accessKeys = new ArrayList<>();
        user6.userName=userName6;
        user6.accessKeys.add(useraksk6.accessKey);
        HBaseUtils.put(user6);
        
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName1, policyString1,200);
        
        
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*Bucket*"),"Resource",Arrays.asList("arn:ctyun:oos::*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName2, policyString2,200);
        
        
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*Object*"),"Resource",Arrays.asList("arn:ctyun:oos::*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3,200);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName3, policyString3,200);
        
        
        String policyString4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:DeleteObject"),"Resource",Arrays.asList("arn:ctyun:oos::*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName4, policyString4,200);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName4, policyString4,200);
        
        
        String policyString5=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName5, policyString5,200);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName5, policyString5,200);
 
        
        String policyString6=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:*Bucket*"),"Resource",Arrays.asList("arn:ctyun:oos::*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName6, policyString6,200);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName6, policyString6,200);
//        
        VSNTagMeta dataTag1;
        VSNTagMeta metaTag1;
        
        
        dataTag1 = new VSNTagMeta("tag1", Arrays.asList(new String[] { "yxregion1","yxregion2"}), VSNTagType.DATA);
        metaClient.vsnTagInsert(dataTag1);
        metaTag1 = new VSNTagMeta("mtag1", Arrays.asList(new String[] { "yxregion1" }), VSNTagType.META);
        metaClient.vsnTagInsert(metaTag1);
        
        OwnerMeta owner1 = new OwnerMeta(ownerName);
        OwnerMeta owner2 = new OwnerMeta(ownerName2);
        UserToTagMeta user1Tag1 = new UserToTagMeta(owner1.getId(),
                Arrays.asList(new String[] { dataTag1.getTagName() }), VSNTagType.DATA);
        metaClient.userToTagInsert(user1Tag1);
        UserToTagMeta user1Tag2 = new UserToTagMeta(owner1.getId(),
                Arrays.asList(new String[] { metaTag1.getTagName() }), VSNTagType.META);
        metaClient.userToTagInsert(user1Tag2);
        
        UserToTagMeta user2Tag1 = new UserToTagMeta(owner2.getId(),
                Arrays.asList(new String[] { dataTag1.getTagName() }), VSNTagType.DATA);
        metaClient.userToTagInsert(user2Tag1);
        UserToTagMeta user2Tag2 = new UserToTagMeta(owner2.getId(),
                Arrays.asList(new String[] { metaTag1.getTagName() }), VSNTagType.META);
        metaClient.userToTagInsert(user2Tag2);
        
        OOSInterfaceTestUtils.Bucket_Put("http", "V4", 80, accessKey, secretKey, bucketName1, null, null, null, null, null);
        OOSInterfaceTestUtils.Bucket_Put("http", "V4", 80, accessKey2, secretKey2, bucketName2, null, null, null, null, null);

    }

    @Test
    /*
     * 超过5个顶出非白名单的第一个
     */
    public void test_1_old() throws InterruptedException {
        // 给第六个用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user5Name, policyName3, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName4, 200);
       
        Thread.sleep(2000);
        // 6个用户进行oos api操作
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 日志结果
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloospolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583914958040","Statement":[{"Sid":"1583914958040_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583914959733","Statement":[{"Sid":"1583914959733_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|alloospolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583914958040","Statement":[{"Sid":"1583914958040_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583914959733","Statement":[{"Sid":"1583914959733_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583914960220","Statement":[{"Sid":"1583914960220_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------remove cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                ------------------remove cache:key=098kw0mm2j4p8|alloospolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583914960736","Statement":[{"Sid":"1583914960736_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
        
        

        Thread.sleep(11000);
        // 在cache
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);

        // 不在cache
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        // 日志结果 
//                ------------------in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------in cache:key=3fdmxmc3pqvmp|alloospolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583914958040","Statement":[{"Sid":"1583914958040_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583914959733","Statement":[{"Sid":"1583914959733_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|alloospolicy
//                ------------------remove cache:key=098kw0mm2j4p8|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583914958040","Statement":[{"Sid":"1583914958040_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=098kw0mm2j4p8|test_5
//                ------------------in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583914960220","Statement":[{"Sid":"1583914960220_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=098kw0mm2j4p8|test_6
//                ------------------in cache:key=098kw0mm2j4p8|denydeleteobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583914960736","Statement":[{"Sid":"1583914960736_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------remove cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|alloosbucketpolicy
//                ------------------remove cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583914959733","Statement":[{"Sid":"1583914959733_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1


    }
    
    @Test
    /*
     * 白名单的detach之后还在白名单里
     */
    public void test_2_old() throws InterruptedException {
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user5Name, policyName3, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName4, 200);
       
        Thread.sleep(2000);
        // 6个用户进行oos api操作
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 日志结果
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloospolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583915771509","Statement":[{"Sid":"1583915771509_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583915773175","Statement":[{"Sid":"1583915773175_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|alloospolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583915771509","Statement":[{"Sid":"1583915771509_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583915773175","Statement":[{"Sid":"1583915773175_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583915773725","Statement":[{"Sid":"1583915773725_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------remove cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                ------------------remove cache:key=098kw0mm2j4p8|alloospolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583915774322","Statement":[{"Sid":"1583915774322_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1

        Thread.sleep(11000);
        
       // detach user1 policy
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        
       // detach user6 policy
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName4, 200);
        

        // 
        Thread.sleep(11000);
        
        // 在cache
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        
        // 日志结果
//      ------------------in cache:key=3fdmxmc3pqvmp|test_2
//      ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//      -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583915773175","Statement":[{"Sid":"1583915773175_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//      -----------------------cache size=1
//      ------------------in cache:key=098kw0mm2j4p8|test_3
//      ------------------not in cache:key=098kw0mm2j4p8|alloospolicy
//      ------------------remove cache:key=098kw0mm2j4p8|alloosbucketpolicy
//      -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583915771509","Statement":[{"Sid":"1583915771509_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//      -----------------------cache size=1
//      ------------------in cache:key=098kw0mm2j4p8|test_5
//      ------------------in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//      -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583915773725","Statement":[{"Sid":"1583915773725_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//      -----------------------cache size=1

        // 在cache 白名单
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        
        // 在cache中，但列表为[]
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 日志结果
//                ------------------in cache:key=3fdmxmc3pqvmp|test_1
//                -----------------------cache size=0
//                ------------------in cache:key=098kw0mm2j4p8|test_6
//                -----------------------cache size=0

        // 3倍timeout之后清除。这里用41是因为真正清理时间本机测试为35秒之后。时间上虽然有延迟一些，但功能没有问题，可以接受延迟。
        Thread.sleep(61000);
        
        // 在cache 白名单
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        
        // 不在cache
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 日志结果
//                ------------------remove expire cache:key=098kw0mm2j4p8|alloospolicy
//                ------------------remove expire cache:key=098kw0mm2j4p8|test_5
//                ------------------remove expire cache:key=098kw0mm2j4p8|test_6
//                ------------------remove expire cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------remove expire cache:key=098kw0mm2j4p8|denydeleteobject
//
//                ------------------in cache:key=3fdmxmc3pqvmp|test_1
//                -----------------------cache size=0
//                ------------------in cache:key=098kw0mm2j4p8|test_6
//                -----------------------cache size=0
                

    }
    
    @Test
    /*
     * 更新用户权限cachetimeout前不生效，cachetimeout之后生效
     */
    public void test_3_old() throws InterruptedException {
        // 给第六个用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user5Name, policyName3, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName4, 200);
       
        Thread.sleep(2000);
        // 6个用户进行oos api操作
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);

        // 日志结果
//              ------------------not in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloospolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583904813699","Statement":[{"Sid":"1583904813699_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583904817572","Statement":[{"Sid":"1583904817572_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|alloospolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583904813699","Statement":[{"Sid":"1583904813699_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583904817572","Statement":[{"Sid":"1583904817572_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583904818202","Statement":[{"Sid":"1583904818202_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------remove cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                ------------------remove cache:key=098kw0mm2j4p8|alloospolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583904818853","Statement":[{"Sid":"1583904818853_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
        
        Thread.sleep(11000);
        
       // 修改 user1 policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName5, 200);
        
       // 修改 user6 policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName6, 200);
        
       // 等待 timeout时间
        Thread.sleep(11000);
        
       
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        //  日志结果
//                ------------------in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------not in cache:key=3fdmxmc3pqvmp|denyputobject
//                ------------------remove cache:key=098kw0mm2j4p8|alloosbucketpolicy
//                ------------------in cache:key=3fdmxmc3pqvmp|alloospolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583904819521","Statement":[{"Sid":"1583904819521_1","Effect":"Deny","Action":"oos:PutObject","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583904813699","Statement":[{"Sid":"1583904813699_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------in cache:key=098kw0mm2j4p8|test_6
//                ------------------in cache:key=098kw0mm2j4p8|denydeleteobject
//                ------------------not in cache:key=098kw0mm2j4p8|denybucket
//                ------------------remove cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583904818853","Statement":[{"Sid":"1583904818853_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583904820264","Statement":[{"Sid":"1583904820264_1","Effect":"Deny","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2

    }
    
    @Test
    /*
     * 三倍timeout之后清除，dead cache
     */
    public void test_4_old() throws InterruptedException {
     // 给第六个用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user5Name, policyName3, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName4, 200);
       
        Thread.sleep(2000);
        // 6个用户进行oos api操作
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 日志结果
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloospolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583905520140","Statement":[{"Sid":"1583905520140_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583905521793","Statement":[{"Sid":"1583905521793_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|alloospolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583905520140","Statement":[{"Sid":"1583905520140_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583905521793","Statement":[{"Sid":"1583905521793_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583905522507","Statement":[{"Sid":"1583905522507_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------remove cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                ------------------remove cache:key=098kw0mm2j4p8|alloospolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583905523087","Statement":[{"Sid":"1583905523087_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
       
        // 等待 timeout*3时间
        Thread.sleep(41000);
        
        // 6个用户都调用oos api接口
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        

        // 日志结果
//                ------------------remove expire cache:key=098kw0mm2j4p8|test_5
//                ------------------remove expire cache:key=098kw0mm2j4p8|test_6
//                ------------------remove expire cache:key=098kw0mm2j4p8|alloosbucketpolicy
//                ------------------remove expire cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------remove expire cache:key=098kw0mm2j4p8|denydeleteobject
//
//
//                ------------------in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------in cache:key=3fdmxmc3pqvmp|alloospolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583905520140","Statement":[{"Sid":"1583905520140_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583905521793","Statement":[{"Sid":"1583905521793_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|alloospolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583905520140","Statement":[{"Sid":"1583905520140_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583905522507","Statement":[{"Sid":"1583905522507_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583905523087","Statement":[{"Sid":"1583905523087_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1


        
    }
    
    @Test
    /*
     * 超过5个顶出非白名单的第一个，其中两个没有policy
     */
    public void test_5_old() throws InterruptedException {
        // 给第六个用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName2, 200);
               
        Thread.sleep(2000);
        // 6个用户进行oos api操作
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);

        // 查看日志
////              ------------------not in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloospolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583905917781","Statement":[{"Sid":"1583905917781_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583905919709","Statement":[{"Sid":"1583905919709_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|alloospolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583905917781","Statement":[{"Sid":"1583905917781_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583905919709","Statement":[{"Sid":"1583905919709_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                -----------------------cache size=0
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------remove cache:key=098kw0mm2j4p8|test_4
//                -----------------------cache size=0
        
        Thread.sleep(11000);
        // 在cache
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);

        // 不在cache
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        
        // 查看日志 
//                ------------------in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------in cache:key=3fdmxmc3pqvmp|alloospolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583905917781","Statement":[{"Sid":"1583905917781_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583905919709","Statement":[{"Sid":"1583905919709_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=098kw0mm2j4p8|test_3
//                ------------------in cache:key=098kw0mm2j4p8|alloospolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583905917781","Statement":[{"Sid":"1583905917781_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=098kw0mm2j4p8|test_5
//                -----------------------cache size=0
//                ------------------in cache:key=098kw0mm2j4p8|test_6
//                -----------------------cache size=0
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------remove cache:key=098kw0mm2j4p8|test_5
//                ------------------in cache:key=098kw0mm2j4p8|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583905919709","Statement":[{"Sid":"1583905919709_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1

    }
    
    @Test
    /*
     * 更新用户权限cachetimeout前不生效，cachetimeout之后生效，一个用户detach之后attach
     */
    public void test_6_old() throws InterruptedException {
        // 给第六个用户添加policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user5Name, policyName3, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName4, 200);
       
        Thread.sleep(2000);
        // 6个用户进行oos api操作
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);

        // 日志结果

//                ------------------not in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloospolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583906174606","Statement":[{"Sid":"1583906174606_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583906176237","Statement":[{"Sid":"1583906176237_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|alloospolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583906174606","Statement":[{"Sid":"1583906174606_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583906176237","Statement":[{"Sid":"1583906176237_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583906177086","Statement":[{"Sid":"1583906177086_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------remove cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                ------------------remove cache:key=098kw0mm2j4p8|alloospolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583906177798","Statement":[{"Sid":"1583906177798_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
        
        Thread.sleep(11000);
        
       // 修改 user1 policy
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName5, 200);
        
       // 修改 user6 policy
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName6, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName4, 200);
        
       // 等待 timeout时间
        Thread.sleep(11000);
        
       //  
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 日志结果
//                ------------------in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------not in cache:key=3fdmxmc3pqvmp|denyputobject
//                ------------------remove cache:key=098kw0mm2j4p8|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583906178412","Statement":[{"Sid":"1583906178412_1","Effect":"Deny","Action":"oos:PutObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=098kw0mm2j4p8|test_6
//                ------------------not in cache:key=098kw0mm2j4p8|denybucket
//                ------------------remove cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583906179031","Statement":[{"Sid":"1583906179031_1","Effect":"Deny","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
    }
    
    @Test
    /*
     *超过5个顶出非白名单的第一个
     */
    public void test_7() {
        String groupName1="group01";
        String groupName2="group02";
        String groupName3="group03";
        String groupName4="group04";
        String groupName5="group05";
        String groupName6="group06";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName1, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName2, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName3, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName4, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName5, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName6, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName2, 200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName1, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user2Name, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName3, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName4, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user5Name, policyName5, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName6, 200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName3, policyName3, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName5, policyName5, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName3, user3Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName4, user3Name, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName3, user4Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName4, user4Name, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName5, user5Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName6, user6Name, 200);
        
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 查看日志
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------not in cache:key=3fdmxmc3pqvmp|group01
//                ------------------not in cache:key=3fdmxmc3pqvmp|group02
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloospolicy
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583910866166","Statement":[{"Sid":"1583910866166_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583910867927","Statement":[{"Sid":"1583910867927_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583910867927","Statement":[{"Sid":"1583910867927_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|group04
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583910868539","Statement":[{"Sid":"1583910868539_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------in cache:key=098kw0mm2j4p8|group03
//                ------------------in cache:key=098kw0mm2j4p8|group04
//                ------------------in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583910868539","Statement":[{"Sid":"1583910868539_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583910869076","Statement":[{"Sid":"1583910869076_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|group05
//                ------------------not in cache:key=098kw0mm2j4p8|denyputobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583910869522","Statement":[{"Sid":"1583910869522_1","Effect":"Deny","Action":"oos:PutObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------remove cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|group06
//                ------------------remove cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|denybucket
//                ------------------remove cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583910870127","Statement":[{"Sid":"1583910870127_1","Effect":"Deny","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
        
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 查看日志
//                ------------------in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------in cache:key=3fdmxmc3pqvmp|group01
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------in cache:key=3fdmxmc3pqvmp|alloospolicy
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583910866166","Statement":[{"Sid":"1583910866166_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583910867927","Statement":[{"Sid":"1583910867927_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583910867927","Statement":[{"Sid":"1583910867927_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|group03
//                ------------------remove cache:key=098kw0mm2j4p8|group04
//                ------------------not in cache:key=098kw0mm2j4p8|group04
//                ------------------remove cache:key=098kw0mm2j4p8|group05
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------remove cache:key=098kw0mm2j4p8|denydeleteobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583910868539","Statement":[{"Sid":"1583910868539_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------remove cache:key=098kw0mm2j4p8|test_5
//                ------------------in cache:key=098kw0mm2j4p8|group03
//                ------------------in cache:key=098kw0mm2j4p8|group04
//                ------------------in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                ------------------remove cache:key=098kw0mm2j4p8|denyputobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583910868539","Statement":[{"Sid":"1583910868539_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583910869076","Statement":[{"Sid":"1583910869076_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                ------------------remove cache:key=098kw0mm2j4p8|test_6
//                ------------------not in cache:key=098kw0mm2j4p8|group05
//                ------------------remove cache:key=098kw0mm2j4p8|group06
//                ------------------not in cache:key=098kw0mm2j4p8|denyputobject
//                ------------------remove cache:key=098kw0mm2j4p8|denybucket
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583910869522","Statement":[{"Sid":"1583910869522_1","Effect":"Deny","Action":"oos:PutObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------remove cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|group06
//                ------------------remove cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|denybucket
//                ------------------remove cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583910870127","Statement":[{"Sid":"1583910870127_1","Effect":"Deny","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
        
    }
    
    @Test
    /*
     *白名单的detach之后还在白名单里
     */
    public void test_8() throws InterruptedException {
        String groupName1="group01";
        String groupName2="group02";
        String groupName3="group03";
        String groupName4="group04";
        String groupName5="group05";
        String groupName6="group06";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName1, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName2, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName3, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName4, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName5, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName6, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName2, 200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName1, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user2Name, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName3, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName4, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user5Name, policyName5, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName6, 200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName3, policyName3, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName5, policyName5, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName3, user3Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName4, user3Name, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName3, user4Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName4, user4Name, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName5, user5Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName6, user6Name, 200);
        
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 查看日志
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------not in cache:key=3fdmxmc3pqvmp|group01
//                ------------------not in cache:key=3fdmxmc3pqvmp|group02
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloospolicy
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583910866166","Statement":[{"Sid":"1583910866166_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583910867927","Statement":[{"Sid":"1583910867927_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583910867927","Statement":[{"Sid":"1583910867927_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|group04
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583910868539","Statement":[{"Sid":"1583910868539_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------in cache:key=098kw0mm2j4p8|group03
//                ------------------in cache:key=098kw0mm2j4p8|group04
//                ------------------in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583910868539","Statement":[{"Sid":"1583910868539_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583910869076","Statement":[{"Sid":"1583910869076_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|group05
//                ------------------not in cache:key=098kw0mm2j4p8|denyputobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583910869522","Statement":[{"Sid":"1583910869522_1","Effect":"Deny","Action":"oos:PutObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------remove cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|group06
//                ------------------remove cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|denybucket
//                ------------------remove cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583910870127","Statement":[{"Sid":"1583910870127_1","Effect":"Deny","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
        
        Thread.sleep(11000);
        // detach user1 policy
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName2, 200);
        
        Thread.sleep(11000);
        // detach user6 policy
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName4, 200);
        IAMInterfaceTestUtils.DetachGroupPolicy(accessKey2, secretKey2, accountId2, groupName3, policyName3, 200);
  
        
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 查看日志
//                ------------------in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583917245610","Statement":[{"Sid":"1583917245610_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|group03
//                ------------------remove cache:key=098kw0mm2j4p8|group04
//                ------------------not in cache:key=098kw0mm2j4p8|group04
//                ------------------remove cache:key=098kw0mm2j4p8|group05
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------remove cache:key=098kw0mm2j4p8|denydeleteobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583917246274","Statement":[{"Sid":"1583917246274_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=098kw0mm2j4p8|test_6
//                ------------------in cache:key=098kw0mm2j4p8|group06
//                ------------------in cache:key=098kw0mm2j4p8|denybucket
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583917248297","Statement":[{"Sid":"1583917248297_1","Effect":"Deny","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
        
        Thread.sleep(61000);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        
        // 查看日志
//                ------------------remove expire cache:key=098kw0mm2j4p8|test_5
//                ------------------remove expire cache:key=098kw0mm2j4p8|denyputobject
//                ------------------remove expire cache:key=098kw0mm2j4p8|test_6
//                ------------------remove expire cache:key=098kw0mm2j4p8|group06
//                ------------------remove expire cache:key=098kw0mm2j4p8|group03
//                ------------------remove expire cache:key=098kw0mm2j4p8|group04
//                ------------------remove expire cache:key=098kw0mm2j4p8|denybucket
//                ------------------remove expire cache:key=098kw0mm2j4p8|alloosobjectpolicy
//
//                ------------------in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------in cache:key=3fdmxmc3pqvmp|group01
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                -----------------------cache size=0
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|group04
//                -----------------------cache size=0

    }
    
    @Test
    /*
     *更新用户权限cachetimeout前不生效，cachetimeout之后生效
     */
    public void test_9() throws InterruptedException {
        String groupName1="group01";
        String groupName2="group02";
        String groupName3="group03";
        String groupName4="group04";
        String groupName5="group05";
        String groupName6="group06";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName1, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName2, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName3, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName4, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName5, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName6, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName2, 200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName1, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user2Name, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName3, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName4, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user5Name, policyName5, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName6, 200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName3, policyName3, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName5, policyName5, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName3, user3Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName4, user3Name, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName3, user4Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName4, user4Name, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName5, user5Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName6, user6Name, 200);
        
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 查看日志
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------not in cache:key=3fdmxmc3pqvmp|group01
//                ------------------not in cache:key=3fdmxmc3pqvmp|group02
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloospolicy
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583910866166","Statement":[{"Sid":"1583910866166_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583910867927","Statement":[{"Sid":"1583910867927_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583910867927","Statement":[{"Sid":"1583910867927_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|group04
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583910868539","Statement":[{"Sid":"1583910868539_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------in cache:key=098kw0mm2j4p8|group03
//                ------------------in cache:key=098kw0mm2j4p8|group04
//                ------------------in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583910868539","Statement":[{"Sid":"1583910868539_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583910869076","Statement":[{"Sid":"1583910869076_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|group05
//                ------------------not in cache:key=098kw0mm2j4p8|denyputobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583910869522","Statement":[{"Sid":"1583910869522_1","Effect":"Deny","Action":"oos:PutObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------remove cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|group06
//                ------------------remove cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|denybucket
//                ------------------remove cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583910870127","Statement":[{"Sid":"1583910870127_1","Effect":"Deny","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
        
        Thread.sleep(11000);
        
        // 修改 user1 policy
         IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName5, 200);
         IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName3, 200);
         
        // 修改 user6 policy
         IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName6, 200);
         IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName4, policyName5, 200);
         
        // 等待 timeout时间
         Thread.sleep(11000);
        
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null); 
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        
        // 查看日志
//                ------------------in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------in cache:key=3fdmxmc3pqvmp|group01
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------not in cache:key=3fdmxmc3pqvmp|denyputobject
//                ------------------remove cache:key=098kw0mm2j4p8|denydeleteobject
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloosobjectpolicy
//                ------------------remove cache:key=098kw0mm2j4p8|denyputobject
//                ------------------in cache:key=3fdmxmc3pqvmp|alloospolicy
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583918397654","Statement":[{"Sid":"1583918397654_1","Effect":"Deny","Action":"oos:PutObject","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583918396341","Statement":[{"Sid":"1583918396341_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583918393933","Statement":[{"Sid":"1583918393933_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583918395714","Statement":[{"Sid":"1583918395714_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=4
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------remove cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|group03
//                ------------------remove cache:key=098kw0mm2j4p8|group04
//                ------------------not in cache:key=098kw0mm2j4p8|group04
//                ------------------remove cache:key=098kw0mm2j4p8|group05
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------remove cache:key=098kw0mm2j4p8|denybucket
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                ------------------remove cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------not in cache:key=098kw0mm2j4p8|denyputobject
//                ------------------remove cache:key=098kw0mm2j4p8|denydeleteobject
//                ------------------not in cache:key=098kw0mm2j4p8|denybucket
//                ------------------remove cache:key=098kw0mm2j4p8|denyputobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583918396341","Statement":[{"Sid":"1583918396341_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583918397043","Statement":[{"Sid":"1583918397043_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583918397654","Statement":[{"Sid":"1583918397654_1","Effect":"Deny","Action":"oos:PutObject","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583918398283","Statement":[{"Sid":"1583918398283_1","Effect":"Deny","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=4
        
    }
    
    @Test
    /*
     *三倍timeout之后清除，dead cache
     */
    public void test_10() throws InterruptedException {
        String groupName1="group01";
        String groupName2="group02";
        String groupName3="group03";
        String groupName4="group04";
        String groupName5="group05";
        String groupName6="group06";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName1, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName2, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName3, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName4, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName5, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName6, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName2, 200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName1, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user2Name, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName3, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName4, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user5Name, policyName5, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName6, 200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName3, policyName3, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName5, policyName5, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName3, user3Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName4, user3Name, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName3, user4Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName4, user4Name, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName5, user5Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName6, user6Name, 200);
        
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 查看日志
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------not in cache:key=3fdmxmc3pqvmp|group01
//                ------------------not in cache:key=3fdmxmc3pqvmp|group02
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloospolicy
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583910866166","Statement":[{"Sid":"1583910866166_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583910867927","Statement":[{"Sid":"1583910867927_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583910867927","Statement":[{"Sid":"1583910867927_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|group04
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583910868539","Statement":[{"Sid":"1583910868539_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------in cache:key=098kw0mm2j4p8|group03
//                ------------------in cache:key=098kw0mm2j4p8|group04
//                ------------------in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583910868539","Statement":[{"Sid":"1583910868539_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583910869076","Statement":[{"Sid":"1583910869076_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|group05
//                ------------------not in cache:key=098kw0mm2j4p8|denyputobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583910869522","Statement":[{"Sid":"1583910869522_1","Effect":"Deny","Action":"oos:PutObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------remove cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|group06
//                ------------------remove cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|denybucket
//                ------------------remove cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583910870127","Statement":[{"Sid":"1583910870127_1","Effect":"Deny","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
        Thread.sleep(41000);
        
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 查看日志
//                ------------------remove expire cache:key=098kw0mm2j4p8|test_5
//                ------------------remove expire cache:key=098kw0mm2j4p8|test_6
//                ------------------remove expire cache:key=098kw0mm2j4p8|group04
//                ------------------remove expire cache:key=098kw0mm2j4p8|group05
//                ------------------remove expire cache:key=098kw0mm2j4p8|group06
//                ------------------remove expire cache:key=098kw0mm2j4p8|denydeleteobject
//                ------------------remove expire cache:key=098kw0mm2j4p8|denyputobject
//                ------------------remove expire cache:key=098kw0mm2j4p8|denybucket
//
//                ------------------in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------in cache:key=3fdmxmc3pqvmp|group01
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------in cache:key=3fdmxmc3pqvmp|alloospolicy
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583918655415","Statement":[{"Sid":"1583918655415_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583918657145","Statement":[{"Sid":"1583918657145_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583918657145","Statement":[{"Sid":"1583918657145_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|group04
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583918657794","Statement":[{"Sid":"1583918657794_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------in cache:key=098kw0mm2j4p8|group03
//                ------------------in cache:key=098kw0mm2j4p8|group04
//                ------------------in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583918657794","Statement":[{"Sid":"1583918657794_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583918658418","Statement":[{"Sid":"1583918658418_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|group05
//                ------------------not in cache:key=098kw0mm2j4p8|denyputobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583918659052","Statement":[{"Sid":"1583918659052_1","Effect":"Deny","Action":"oos:PutObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------remove cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|group06
//                ------------------remove cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|denybucket
//                ------------------remove cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583918659637","Statement":[{"Sid":"1583918659637_1","Effect":"Deny","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
    
    }
    
    @Test
    /*
     *更新用户权限cachetimeout前不生效，cachetimeout之后生效，一个用户detach之后attach
     */
    public void test_11() throws InterruptedException {
        String groupName1="group01";
        String groupName2="group02";
        String groupName3="group03";
        String groupName4="group04";
        String groupName5="group05";
        String groupName6="group06";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName1, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName2, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName3, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName4, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName5, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName6, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName2, 200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName1, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user2Name, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName3, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName4, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user5Name, policyName5, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName6, 200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName3, policyName3, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName5, policyName5, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName3, user3Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName4, user3Name, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName3, user4Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName4, user4Name, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName5, user5Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName6, user6Name, 200);
        
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 查看日志
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------not in cache:key=3fdmxmc3pqvmp|group01
//                ------------------not in cache:key=3fdmxmc3pqvmp|group02
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloospolicy
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583910866166","Statement":[{"Sid":"1583910866166_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583910867927","Statement":[{"Sid":"1583910867927_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583910867927","Statement":[{"Sid":"1583910867927_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|group04
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583910868539","Statement":[{"Sid":"1583910868539_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------in cache:key=098kw0mm2j4p8|group03
//                ------------------in cache:key=098kw0mm2j4p8|group04
//                ------------------in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583910868539","Statement":[{"Sid":"1583910868539_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583910869076","Statement":[{"Sid":"1583910869076_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|group05
//                ------------------not in cache:key=098kw0mm2j4p8|denyputobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583910869522","Statement":[{"Sid":"1583910869522_1","Effect":"Deny","Action":"oos:PutObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------remove cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|group06
//                ------------------remove cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|denybucket
//                ------------------remove cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583910870127","Statement":[{"Sid":"1583910870127_1","Effect":"Deny","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
        
        Thread.sleep(11000);
        // detach user1 policy
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName2, 200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName1, user1Name, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName3, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId1, groupName2, policyName4, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user1Name, 200);
        
        // detach user6 policy
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName4, 200);
        IAMInterfaceTestUtils.DetachGroupPolicy(accessKey2, secretKey2, accountId2, groupName3, policyName3, 200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey2, secretKey2, groupName3, user4Name, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName5, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName4, policyName5, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName4, user4Name, 200);
     
        Thread.sleep(11000);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        
        // 查看日志
//                ------------------remove expire cache:key=098kw0mm2j4p8|test_5
//                ------------------remove expire cache:key=098kw0mm2j4p8|test_6
//                ------------------remove expire cache:key=098kw0mm2j4p8|group04
//                ------------------remove expire cache:key=098kw0mm2j4p8|group05
//                ------------------remove expire cache:key=098kw0mm2j4p8|group06
//                ------------------remove expire cache:key=098kw0mm2j4p8|denydeleteobject
//                ------------------remove expire cache:key=098kw0mm2j4p8|denyputobject
//                ------------------remove expire cache:key=098kw0mm2j4p8|denybucket
//
//                ------------------in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloosobjectpolicy
//                ------------------not in cache:key=3fdmxmc3pqvmp|denydeleteobject
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583919197565","Statement":[{"Sid":"1583919197565_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583919198284","Statement":[{"Sid":"1583919198284_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|group04
//                ------------------not in cache:key=098kw0mm2j4p8|denyputobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583919199078","Statement":[{"Sid":"1583919199078_1","Effect":"Deny","Action":"oos:PutObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1

    }
    
    @Test
    /*
     * 更新policy内容，cache更新
     */
    public void test_12() throws InterruptedException {
        String groupName1="group01";
        String groupName2="group02";
        String groupName3="group03";
        String groupName4="group04";
        String groupName5="group05";
        String groupName6="group06";
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName1, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName2, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName3, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName4, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName5, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName6, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName2, 200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName1, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user2Name, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName3, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName4, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user5Name, policyName5, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName6, 200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName3, policyName3, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName5, policyName5, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName3, user3Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName4, user3Name, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName3, user4Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName4, user4Name, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName5, user5Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName6, user6Name, 200);
        
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user5accessKey, user5secretKey, bucketName2, "5.txt", "user5object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user6accessKey, user6secretKey, bucketName2, "6.txt", "user6object", null);
        
        // 查看日志
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------not in cache:key=3fdmxmc3pqvmp|group01
//                ------------------not in cache:key=3fdmxmc3pqvmp|group02
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloospolicy
//                ------------------not in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583910866166","Statement":[{"Sid":"1583910866166_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583910867927","Statement":[{"Sid":"1583910867927_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583910867927","Statement":[{"Sid":"1583910867927_1","Effect":"Allow","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|group04
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583910868539","Statement":[{"Sid":"1583910868539_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------in cache:key=098kw0mm2j4p8|group03
//                ------------------in cache:key=098kw0mm2j4p8|group04
//                ------------------in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583910868539","Statement":[{"Sid":"1583910868539_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583910869076","Statement":[{"Sid":"1583910869076_1","Effect":"Deny","Action":"oos:DeleteObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------not in cache:key=098kw0mm2j4p8|test_5
//                ------------------not in cache:key=098kw0mm2j4p8|group05
//                ------------------not in cache:key=098kw0mm2j4p8|denyputobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_5,policy={"Version":"2012-10-17","Id":"1583910869522","Statement":[{"Sid":"1583910869522_1","Effect":"Deny","Action":"oos:PutObject","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_6
//                ------------------remove cache:key=098kw0mm2j4p8|test_4
//                ------------------not in cache:key=098kw0mm2j4p8|group06
//                ------------------remove cache:key=098kw0mm2j4p8|group03
//                ------------------not in cache:key=098kw0mm2j4p8|denybucket
//                ------------------remove cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_6,policy={"Version":"2012-10-17","Id":"1583910870127","Statement":[{"Sid":"1583910870127_1","Effect":"Deny","Action":"oos:*Bucket*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
                
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::*"),null);
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::*"),null);
        
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString1, 200);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName4, policyString2, 200);
        
        Thread.sleep(21000);
        
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user1accessKey, user1secretKey, bucketName1, "1.txt", "user1object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user2accessKey, user2secretKey, bucketName1, "2.txt", "user2object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user3accessKey, user3secretKey, bucketName2, "3.txt", "user3object", null);
        OOSInterfaceTestUtils.Object_Put("http", "V4", 80, user4accessKey, user4secretKey, bucketName2, "4.txt", "user4object", null);
        
        // 查看日志
        
//                ------------------in cache:key=3fdmxmc3pqvmp|test_1
//                ------------------in cache:key=3fdmxmc3pqvmp|group01
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------in cache:key=3fdmxmc3pqvmp|alloospolicy
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583980057982","Statement":[{"Sid":"1583980057982_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_1,policy={"Version":"2012-10-17","Id":"1583980101618","Statement":[{"Sid":"1583980101618_1","Effect":"Deny","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
//                ------------------in cache:key=3fdmxmc3pqvmp|test_2
//                ------------------in cache:key=3fdmxmc3pqvmp|group02
//                ------------------in cache:key=3fdmxmc3pqvmp|alloosbucketpolicy
//                -------------------real cache :Key=accountId : 3fdmxmc3pqvmp, userName : test_2,policy={"Version":"2012-10-17","Id":"1583980101618","Statement":[{"Sid":"1583980101618_1","Effect":"Deny","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------in cache:key=098kw0mm2j4p8|test_3
//                ------------------not in cache:key=098kw0mm2j4p8|group03
//                ------------------remove cache:key=098kw0mm2j4p8|group04
//                ------------------not in cache:key=098kw0mm2j4p8|group04
//                ------------------remove cache:key=098kw0mm2j4p8|group05
//                ------------------not in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------remove cache:key=098kw0mm2j4p8|denydeleteobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_3,policy={"Version":"2012-10-17","Id":"1583980060457","Statement":[{"Sid":"1583980060457_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=1
//                ------------------not in cache:key=098kw0mm2j4p8|test_4
//                ------------------remove cache:key=098kw0mm2j4p8|test_5
//                ------------------in cache:key=098kw0mm2j4p8|group03
//                ------------------in cache:key=098kw0mm2j4p8|group04
//                ------------------in cache:key=098kw0mm2j4p8|alloosobjectpolicy
//                ------------------not in cache:key=098kw0mm2j4p8|denydeleteobject
//                ------------------remove cache:key=098kw0mm2j4p8|denyputobject
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583980060457","Statement":[{"Sid":"1583980060457_1","Effect":"Allow","Action":"oos:*Object*","Resource":"arn:ctyun:oos::*"}]}
//                -------------------real cache :Key=accountId : 098kw0mm2j4p8, userName : test_4,policy={"Version":"2012-10-17","Id":"1583980101618","Statement":[{"Sid":"1583980101618_1","Effect":"Allow","Action":"oos:*","Resource":"arn:ctyun:oos::*"}]}
//                -----------------------cache size=2
        
    }
    
    @Test
    public void test_aksk_sizemore() {
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user5Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName1, 200);
        
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user1accessKey, user1secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user2accessKey, user2secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user3accessKey, user3secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user4accessKey, user4secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user5accessKey, user5secretKey, null);

        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user1accessKey, user1secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user2accessKey, user2secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user3accessKey, user3secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user4accessKey, user4secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user5accessKey, user5secretKey, null);
        
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user6accessKey, user6secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user1accessKey, user1secretKey, null);

        // 查看日志
//                ak-------------not in cache key=userak1
//                ak-------------not in cache key=userak2
//                ak-----------size of ak=2
//                ak-----------size of ak=2
//                ak-------------not in cache key=user1ak
//                ak-------------not in cache key=user2ak
//                ak-----------size of ak=4
//                ak-------------not in cache key=user3ak
//                ak-------------not in cache key=user4ak
//                ak-------------not in cache key=user5ak
//                ak-------------in cache key=user1ak
//                ak-------------in cache key=user2ak
//                ak-------------in cache key=user3ak
//                ak-----------size of ak=5
//                ak-------------in cache key=user4ak
//                ak-------------in cache key=user5ak
//                ak-------------not in cache key=user6ak
//                ak-------------not in cache key=user1ak
//                ak-----------size of ak=5
    }
    
    @Test
    public void test_aksk_updatecase() throws Exception {
        // inactive 
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        Pair<Integer, String> before=OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user1accessKey, user1secretKey, null);
        assertEquals(200, before.first().intValue());
        
        IAMInterfaceTestUtils.UpdateAccessKey(accessKey, secretKey, user1accessKey, user1Name, "Inactive", 200);
        Thread.sleep(11000);

        Pair<Integer, String> after=OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user1accessKey, user1secretKey, null);
        assertEquals(403, after.first().intValue());
        // 查看日志
        
//                ak-------------not in cache key=userak11111111111
//                ak-------------not in cache key=userak2
//                ak-------------not in cache key=user1ak1111111111
//                [INFO]( IamChangeEventProcessor.java,74 ) [2020-03-17 14:25:47] [Timer-1] cn.ctyun.oos.hbase.IamChangeEventProcessor - get change events use time 271ms, events : [[accountId=3fdmxmc3pqvmp, name=user1ak1111111111, type=ACCESSKEY, timestamp=1584426315183]]
//                [INFO]( MetaClient.java,149 ) [2020-03-17 14:25:47] [Timer-1] cn.ctyun.oos.hbase.MetaClient - updated accessKey :user1ak1111111111
//                [INFO]( IamChangeEventProcessor.java,74 ) [2020-03-17 14:25:48] [Timer-1] cn.ctyun.oos.hbase.IamChangeEventProcessor - get change events use time 152ms, events : [[accountId=3fdmxmc3pqvmp, name=user1ak1111111111, type=ACCESSKEY, timestamp=1584426315183]]
//                [INFO]( MetaClient.java,149 ) [2020-03-17 14:25:48] [Timer-1] cn.ctyun.oos.hbase.MetaClient - updated accessKey :user1ak1111111111
//                ak-----------size of ak=3
//                ak-------------in cache key=user1ak1111111111
        
        IAMInterfaceTestUtils.UpdateAccessKey(accessKey, secretKey, user1accessKey, user1Name, "Active", 200);
        Thread.sleep(11000);
        
        Pair<Integer, String> after2=OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user1accessKey, user1secretKey, null);
        assertEquals(200, after2.first().intValue());  
        
        //查看日志
        
//                [INFO]( IamChangeEventProcessor.java,74 ) [2020-03-17 14:25:57] [Timer-1] cn.ctyun.oos.hbase.IamChangeEventProcessor - get change events use time 243ms, events : [[accountId=3fdmxmc3pqvmp, name=user1ak1111111111, type=ACCESSKEY, timestamp=1584426326412]]
//                [INFO]( MetaClient.java,149 ) [2020-03-17 14:25:57] [Timer-1] cn.ctyun.oos.hbase.MetaClient - updated accessKey :user1ak1111111111
//                [INFO]( IamChangeEventProcessor.java,74 ) [2020-03-17 14:25:58] [Timer-1] cn.ctyun.oos.hbase.IamChangeEventProcessor - get change events use time 174ms, events : [[accountId=3fdmxmc3pqvmp, name=user1ak1111111111, type=ACCESSKEY, timestamp=1584426326412]]
//                [INFO]( MetaClient.java,149 ) [2020-03-17 14:25:58] [Timer-1] cn.ctyun.oos.hbase.MetaClient - updated accessKey :user1ak1111111111
//                ak-----------size of ak=3
//                ak-------------in cache key=user1ak1111111111
//                ak-----------size of ak=3
        
    }
    
    @Test
    public void test_aksk_updatecase2() throws InterruptedException {
        // 删除ak
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        Pair<Integer, String> before=OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user1accessKey, user1secretKey, null);
        assertEquals(200, before.first().intValue());
        
        IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, user1accessKey, user1Name, 200);
        Thread.sleep(11000);
        
        Pair<Integer, String> after=OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user1accessKey, user1secretKey, null);
        assertEquals(403, after.first().intValue());
        
        // 查看日志
//                ak-------------not in cache key=userak11111111111
//                ak-------------not in cache key=userak2
//                ak-------------not in cache key=user1ak1111111111
//                [INFO]( IamChangeEventProcessor.java,74 ) [2020-03-17 14:38:14] [Timer-1] cn.ctyun.oos.hbase.IamChangeEventProcessor - get change events use time 235ms, events : [[accountId=3fdmxmc3pqvmp, name=user1ak1111111111, type=ACCESSKEY, timestamp=1584427062673]]
//                ak------------not in akdatebase key=user1ak1111111111
//                [INFO]( MetaClient.java,154 ) [2020-03-17 14:38:14] [Timer-1] cn.ctyun.oos.hbase.MetaClient - invalidate accessKey :user1ak1111111111
//                [INFO]( IamChangeEventProcessor.java,74 ) [2020-03-17 14:38:16] [Timer-1] cn.ctyun.oos.hbase.IamChangeEventProcessor - get change events use time 170ms, events : [[accountId=3fdmxmc3pqvmp, name=user1ak1111111111, type=ACCESSKEY, timestamp=1584427062673]]
//                ak-----------size of ak=2
//                ak-------------not in cache key=user1ak1111111111
//                ak-----------size of ak=2
    }
    
    
    @Test
    public void test_aksk_expire() throws InterruptedException {
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user5Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName1, 200);
        
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user1accessKey, user1secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user2accessKey, user2secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user3accessKey, user3secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user4accessKey, user4secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user5accessKey, user5secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user1accessKey, user1secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user2accessKey, user2secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user3accessKey, user3secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user4accessKey, user4secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user5accessKey, user5secretKey, null);

        //查看日志
//                ak-------------not in cache key=user1ak1111111111
//                ak-------------not in cache key=user2ak
//                ak-------------not in cache key=user3ak
//                ak-------------not in cache key=user4ak
//                ak-----------size of ak=5
//                ak-------------not in cache key=user5ak
//                ak-------------in cache key=user1ak1111111111
//                ak-------------in cache key=user2ak
//                ak-------------in cache key=user3ak
//                ak-------------in cache key=user4ak
//                ak-------------in cache key=user5ak
//                ak-----------size of ak=5
//                ak-----------size of ak=5
        
        Thread.sleep(41000);  
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user1accessKey, user1secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user2accessKey, user2secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user3accessKey, user3secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user4accessKey, user4secretKey, null);
        OOSInterfaceTestUtils.Service_Get("http", "V4", 80, user5accessKey, user5secretKey, null);
        
        // 查看日志
//                ak-------------aksk remove expire ak=user1ak1111111111
//                ak-------------aksk remove expire ak=user2ak
//                ak-------------aksk remove expire ak=user3ak
//                ak-------------aksk remove expire ak=user4ak
//                ak-------------aksk remove expire ak=user5ak
//                ak-------------not in cache key=user1ak1111111111
//                ak-------------not in cache key=user2ak
//                ak-------------not in cache key=user3ak
//                ak-------------not in cache key=user4ak
//                ak-------------not in cache key=user5ak
//                ak-----------size of ak=5
        
    }

}
