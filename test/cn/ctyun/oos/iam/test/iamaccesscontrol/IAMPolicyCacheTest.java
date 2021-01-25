package cn.ctyun.oos.iam.test.iamaccesscontrol;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.ctyun.common.cache.Cache;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.metadata.UserToTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta.VSNTagType;
/*
 * 修改配置oosConfig "localCacheMapSize": 5
 * 修改IamServerConfig "cacheTimeout":10000
 * 在文件IAMSingleUpdateCache.java中get方法添加打印日志
 * public Object get(String key) throws IOException {
        // FIXME 测试用，暂时注释
        Cache cache = this.getContent(key);
        if (cache != null) {
            System.out.println("-----------------in IAM cache,"+this.getClass().getName());
            List<String> list =(List<String>)cache.value;
            for (String l : list) {
                System.out.println("-----------------Key="+key+", value="+l);
            }
            System.out.println("-----------------list size="+list.size());
            return cache.value;
        }
        // 没有获取到缓存，加载数据并设置到缓存
        System.out.println("-----------------not in IAM cache,"+this.getClass().getName());
        System.out.println("-----------------Key="+key);
        Object value = load(key);
        this.putCache(key, new Cache(key, value));
        return value;
    }
 *
 *在文件PolicyDocumentCache.java文件中添加打印日志
 *public Map<String, String> getPolicyDocuments(Set<String> policyKeys) throws IOException {
        Map<String, String> resultMap = new HashMap<>();
        // 记录缓存中没有获取到的数据
        List<String> noCacheList = new ArrayList<>();
        for (String policyKey : policyKeys) {
            // FIXME 测试用，暂时注释
            Cache cache = this.getContent(policyKey);
            if (cache == null || cache.value == null) {
                noCacheList.add(policyKey);
                System.out.println("-----------------not in IAM cache,"+this.getClass().getName());
                System.out.println("-----------------Key="+policyKey);
            } else {
                // 将从缓存中获取到的值放入map中
                resultMap.put(policyKey, cache.value.toString());
                System.out.println("-----------------in IAM cache,"+this.getClass().getName());
                System.out.println("-----------------Key="+policyKey+",value="+cache.value.toString());
            }
        }
 */
public class IAMPolicyCacheTest {
    private static String ownerName = "root_user1@test.com";
    public static final String accessKey="userak1";
    public static final String secretKey="usersk1";
    
    private static String ownerName2 = "root_user2@test.com";
    public static final String accessKey2="userak2";
    public static final String secretKey2="usersk2";
    
    public static final String user1Name="test_1";
    public static final String user2Name="test_2";
    public static final String user3Name="test_3";
    public static final String user4Name="test_4";
    public static final String user5Name="test_5";
    public static final String user6Name="test_6";

    public static final String user1accessKey="user1ak";
    public static final String user1secretKey="user1sk";
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
    
    public static final String policyName1="allIAMPolicy";
    public static final String policyName2="allIAMGroupPolicy";
    public static final String policyName3="allIAMUserPolicy";
    public static final String policyName4="allIAMPolicyPolicy";
    public static final String policyName5="DenyDelete";
    public static final String policyName6="DenyList";
    
    public static final String groupName1="group1";
    public static final String groupName2="group2";
    public static final String groupName3="group3";
    public static final String groupName4="group4";
    public static final String groupName5="group5";
    public static final String groupName6="group6";
    
    
    public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static OwnerMeta owner2 = new OwnerMeta(ownerName2);
    public static MetaClient metaClient = MetaClient.getGlobalClient();

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        Clean();
        CreateUserAndPolicy();
    }

    @Before
    public void setUp() throws Exception {
    }

    
    public static void Clean() {
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
           
       }
    
    @Test
    /*
     * 
     */
    public void test_4cahce() {
        // 根用户创建策略
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString,200);
        
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName1, 200);
        
        // 策略附加给组
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName2, 200);
        // 用户加到组
        
        // 策略附加给用户
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        
        // 策略附加给组
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName1, user1Name, 200);
        

        // 子用户listpolicy no cache
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 200);
        
        // 日志结果
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
        
        // in cache
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 200);
        
        // 日志结果
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|alliampolicy
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|group1
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|group1, value=3fdmxmc3pqvmp|alliamgrouppolicy
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy,value={"Version":"2012-10-17","Id":"1570678294729","Statement":[{"Sid":"1570678294729_1","Effect":"Allow","Action":"iam:*Group*","Resource":"*"}]}
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliampolicy,value={"Version":"2012-10-17","Id":"1570678292839","Statement":[{"Sid":"1570678292839_1","Effect":"Allow","Action":"iam:*","Resource":"*"}]}

    }
    
    @Test
    /*
     * 超过5个user
     */
    public void test_UserCache_usermore() {

        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user3accessKey, user3secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user4accessKey, user4secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user5accessKey, user5secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user6accessKey, user6secretKey, 403);
        
        // 查看日志
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        [INFO]( AccessController.java,65 ) [2019-10-10 14:49:28] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::3fdmxmc3pqvmp:policy/*, principal=null, accountId=3fdmxmc3pqvmp, userId=userid1, userName=test_1, currentTime=2019-10-10T06:49:23Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        [INFO]( AccessController.java,65 ) [2019-10-10 14:49:29] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::3fdmxmc3pqvmp:policy/*, principal=null, accountId=3fdmxmc3pqvmp, userId=userid2, userName=test_2, currentTime=2019-10-10T06:49:28Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        [INFO]( AccessController.java,65 ) [2019-10-10 14:49:29] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::098kw0mm2j4p8:policy/*, principal=null, accountId=098kw0mm2j4p8, userId=userid3, userName=test_3, currentTime=2019-10-10T06:49:29Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        [INFO]( AccessController.java,65 ) [2019-10-10 14:49:30] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::098kw0mm2j4p8:policy/*, principal=null, accountId=098kw0mm2j4p8, userId=userid4, userName=test_4, currentTime=2019-10-10T06:49:29Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        [INFO]( AccessController.java,65 ) [2019-10-10 14:49:30] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::098kw0mm2j4p8:policy/*, principal=null, accountId=098kw0mm2j4p8, userId=userid5, userName=test_5, currentTime=2019-10-10T06:49:30Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        [INFO]( AccessController.java,65 ) [2019-10-10 14:49:31] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::098kw0mm2j4p8:policy/*, principal=null, accountId=098kw0mm2j4p8, userId=userid6, userName=test_6, currentTime=2019-10-10T06:49:31Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 

        
        IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user3accessKey, user3secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user4accessKey, user4secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user5accessKey, user5secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user6accessKey, user6secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 403);
        
        // 查看日志
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------list size=0
//        [INFO]( AccessController.java,65 ) [2019-10-10 14:49:31] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::3fdmxmc3pqvmp:policy/*, principal=null, accountId=3fdmxmc3pqvmp, userId=userid2, userName=test_2, currentTime=2019-10-10T06:49:31Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------list size=0
//        [INFO]( AccessController.java,65 ) [2019-10-10 14:49:31] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::098kw0mm2j4p8:policy/*, principal=null, accountId=098kw0mm2j4p8, userId=userid3, userName=test_3, currentTime=2019-10-10T06:49:31Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------list size=0
//        [INFO]( AccessController.java,65 ) [2019-10-10 14:49:31] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::098kw0mm2j4p8:policy/*, principal=null, accountId=098kw0mm2j4p8, userId=userid4, userName=test_4, currentTime=2019-10-10T06:49:31Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------list size=0
//        [INFO]( AccessController.java,65 ) [2019-10-10 14:49:31] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::098kw0mm2j4p8:policy/*, principal=null, accountId=098kw0mm2j4p8, userId=userid5, userName=test_5, currentTime=2019-10-10T06:49:31Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------list size=0
//        [INFO]( AccessController.java,65 ) [2019-10-10 14:49:31] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::098kw0mm2j4p8:policy/*, principal=null, accountId=098kw0mm2j4p8, userId=userid6, userName=test_6, currentTime=2019-10-10T06:49:31Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        [INFO]( AccessController.java,65 ) [2019-10-10 14:49:32] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::3fdmxmc3pqvmp:policy/*, principal=null, accountId=3fdmxmc3pqvmp, userId=userid1, userName=test_1, currentTime=2019-10-10T06:49:31Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 

    }
    
    @Test
    /*
     * 组超过5个
     */
    public void test_UserGroupKeysCache() {
                
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName1, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName2, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName3, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName4, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName5, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName6, 200);
        
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName1, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user2Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName3, user3Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName4, user4Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName5, user5Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName6, user6Name, 200);
        
        IAMInterfaceTestUtils.GetGroup(user1accessKey, user1secretKey, groupName1, 403);
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName2, 403);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName3, 403);
        IAMInterfaceTestUtils.GetGroup(user4accessKey, user4secretKey, groupName4, 403);
        IAMInterfaceTestUtils.GetGroup(user5accessKey, user5secretKey, groupName5, 403);
        IAMInterfaceTestUtils.GetGroup(user6accessKey, user6secretKey, groupName6, 403);
        
        // 查看日志，主要看UserGroupKeysCache相关
//        [INFO]( IAMHttpHandler.java,135 ) [2019-10-10 17:04:52] cn.ctyun.oos.iam.server.IAMHttpHandler - params:GroupName=group1
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//                -----------------Key=3fdmxmc3pqvmp|test_1
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//                -----------------Key=3fdmxmc3pqvmp|test_1
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//                -----------------Key=3fdmxmc3pqvmp|group1
//                [INFO]( AccessController.java,65 ) [2019-10-10 17:04:57] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:GetGroup, resource=arn:ctyun:iam::3fdmxmc3pqvmp:group/group1, principal=null, accountId=3fdmxmc3pqvmp, userId=userid1, userName=test_1, currentTime=2019-10-10T09:04:52Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//                [INFO]( IAMHttpHandler.java,135 ) [2019-10-10 17:04:58] cn.ctyun.oos.iam.server.IAMHttpHandler - params:GroupName=group2
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//                -----------------Key=3fdmxmc3pqvmp|test_2
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//                -----------------Key=3fdmxmc3pqvmp|test_2
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//                -----------------Key=3fdmxmc3pqvmp|group2
//                [INFO]( AccessController.java,65 ) [2019-10-10 17:04:58] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:GetGroup, resource=arn:ctyun:iam::3fdmxmc3pqvmp:group/group2, principal=null, accountId=3fdmxmc3pqvmp, userId=userid2, userName=test_2, currentTime=2019-10-10T09:04:58Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//                [INFO]( IAMHttpHandler.java,135 ) [2019-10-10 17:04:58] cn.ctyun.oos.iam.server.IAMHttpHandler - params:GroupName=group3
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//                -----------------Key=098kw0mm2j4p8|test_3
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//                -----------------Key=098kw0mm2j4p8|test_3
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//                -----------------Key=098kw0mm2j4p8|group3
//                [INFO]( AccessController.java,65 ) [2019-10-10 17:04:59] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:GetGroup, resource=arn:ctyun:iam::098kw0mm2j4p8:group/group3, principal=null, accountId=098kw0mm2j4p8, userId=userid3, userName=test_3, currentTime=2019-10-10T09:04:58Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//                [INFO]( IAMHttpHandler.java,135 ) [2019-10-10 17:04:59] cn.ctyun.oos.iam.server.IAMHttpHandler - params:GroupName=group4
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//                -----------------Key=098kw0mm2j4p8|test_4
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//                -----------------Key=098kw0mm2j4p8|test_4
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//                -----------------Key=098kw0mm2j4p8|group4
//                [INFO]( AccessController.java,65 ) [2019-10-10 17:05:00] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:GetGroup, resource=arn:ctyun:iam::098kw0mm2j4p8:group/group4, principal=null, accountId=098kw0mm2j4p8, userId=userid4, userName=test_4, currentTime=2019-10-10T09:04:59Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//                [INFO]( IAMHttpHandler.java,135 ) [2019-10-10 17:05:00] cn.ctyun.oos.iam.server.IAMHttpHandler - params:GroupName=group5
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//                -----------------Key=098kw0mm2j4p8|test_5
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//                -----------------Key=098kw0mm2j4p8|test_5
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//                -----------------Key=098kw0mm2j4p8|group5
//                [INFO]( AccessController.java,65 ) [2019-10-10 17:05:00] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:GetGroup, resource=arn:ctyun:iam::098kw0mm2j4p8:group/group5, principal=null, accountId=098kw0mm2j4p8, userId=userid5, userName=test_5, currentTime=2019-10-10T09:05:00Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//                [INFO]( IAMHttpHandler.java,135 ) [2019-10-10 17:05:00] cn.ctyun.oos.iam.server.IAMHttpHandler - params:GroupName=group6
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//                -----------------Key=098kw0mm2j4p8|test_6
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//                -----------------Key=098kw0mm2j4p8|test_6
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//                -----------------Key=098kw0mm2j4p8|group6
//                [INFO]( AccessController.java,65 ) [2019-10-10 17:05:01] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:GetGroup, resource=arn:ctyun:iam::098kw0mm2j4p8:group/group6, principal=null, accountId=098kw0mm2j4p8, userId=userid6, userName=test_6, currentTime=2019-10-10T09:05:00Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 

        
        IAMInterfaceTestUtils.GetGroup(user2accessKey, user2secretKey, groupName2, 403);
        IAMInterfaceTestUtils.GetGroup(user3accessKey, user3secretKey, groupName3, 403);
        IAMInterfaceTestUtils.GetGroup(user4accessKey, user4secretKey, groupName4, 403);
        IAMInterfaceTestUtils.GetGroup(user5accessKey, user5secretKey, groupName5, 403);
        IAMInterfaceTestUtils.GetGroup(user6accessKey, user6secretKey, groupName6, 403);
        IAMInterfaceTestUtils.GetGroup(user1accessKey, user1secretKey, groupName1, 403);
        
        // 查看日志，主要看UserGroupKeysCache相关
//        [INFO]( IAMHttpHandler.java,135 ) [2019-10-10 17:05:01] cn.ctyun.oos.iam.server.IAMHttpHandler - params:GroupName=group2
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//                -----------------list size=0
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//                -----------------Key=3fdmxmc3pqvmp|test_2, value=3fdmxmc3pqvmp|group2
//                -----------------list size=1
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//                -----------------list size=0
//                [INFO]( AccessController.java,65 ) [2019-10-10 17:05:01] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:GetGroup, resource=arn:ctyun:iam::3fdmxmc3pqvmp:group/group2, principal=null, accountId=3fdmxmc3pqvmp, userId=userid2, userName=test_2, currentTime=2019-10-10T09:05:01Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//
//                [INFO]( IAMHttpHandler.java,135 ) [2019-10-10 17:05:01] cn.ctyun.oos.iam.server.IAMHttpHandler - params:GroupName=group3
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//                -----------------list size=0
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//                -----------------Key=098kw0mm2j4p8|test_3, value=098kw0mm2j4p8|group3
//                -----------------list size=1
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//                -----------------list size=0
//                [INFO]( AccessController.java,65 ) [2019-10-10 17:05:01] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:GetGroup, resource=arn:ctyun:iam::098kw0mm2j4p8:group/group3, principal=null, accountId=098kw0mm2j4p8, userId=userid3, userName=test_3, currentTime=2019-10-10T09:05:01Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//
//                [INFO]( IAMHttpHandler.java,135 ) [2019-10-10 17:05:01] cn.ctyun.oos.iam.server.IAMHttpHandler - params:GroupName=group4
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//                -----------------list size=0
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//                -----------------Key=098kw0mm2j4p8|test_4, value=098kw0mm2j4p8|group4
//                -----------------list size=1
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//                -----------------list size=0
//                [INFO]( AccessController.java,65 ) [2019-10-10 17:05:01] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:GetGroup, resource=arn:ctyun:iam::098kw0mm2j4p8:group/group4, principal=null, accountId=098kw0mm2j4p8, userId=userid4, userName=test_4, currentTime=2019-10-10T09:05:01Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//
//                [INFO]( IAMHttpHandler.java,135 ) [2019-10-10 17:05:01] cn.ctyun.oos.iam.server.IAMHttpHandler - params:GroupName=group5
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//                -----------------list size=0
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//                -----------------Key=098kw0mm2j4p8|test_5, value=098kw0mm2j4p8|group5
//                -----------------list size=1
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//                -----------------list size=0
//                [INFO]( AccessController.java,65 ) [2019-10-10 17:05:01] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:GetGroup, resource=arn:ctyun:iam::098kw0mm2j4p8:group/group5, principal=null, accountId=098kw0mm2j4p8, userId=userid5, userName=test_5, currentTime=2019-10-10T09:05:01Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//
//                [INFO]( IAMHttpHandler.java,135 ) [2019-10-10 17:05:01] cn.ctyun.oos.iam.server.IAMHttpHandler - params:GroupName=group6
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//                -----------------list size=0
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//                -----------------Key=098kw0mm2j4p8|test_6, value=098kw0mm2j4p8|group6
//                -----------------list size=1
//                -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//                -----------------list size=0
//                [INFO]( AccessController.java,65 ) [2019-10-10 17:05:01] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:GetGroup, resource=arn:ctyun:iam::098kw0mm2j4p8:group/group6, principal=null, accountId=098kw0mm2j4p8, userId=userid6, userName=test_6, currentTime=2019-10-10T09:05:01Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 
//
//                [INFO]( IAMHttpHandler.java,135 ) [2019-10-10 17:05:01] cn.ctyun.oos.iam.server.IAMHttpHandler - params:GroupName=group1
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//                -----------------Key=3fdmxmc3pqvmp|test_1
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//                -----------------Key=3fdmxmc3pqvmp|test_1
//                -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//                -----------------Key=3fdmxmc3pqvmp|group1
//                [INFO]( AccessController.java,65 ) [2019-10-10 17:05:02] cn.ctyun.oos.iam.accesscontroller.AccessController - user has not policies, access implicit deny, requestInfo : RequestInfo [action=iam:GetGroup, resource=arn:ctyun:iam::3fdmxmc3pqvmp:group/group1, principal=null, accountId=3fdmxmc3pqvmp, userId=userid1, userName=test_1, currentTime=2019-10-10T09:05:01Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : 

        
    }
    
    @Test
    /*
     * 策略超过5个
     */
    public void test_AttachUserPolicyKeysCache() {
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString,200);
        
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*User*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName3, policyString3,200);
        
        String policyString4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Polic*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName4, policyString4,200);
        
        String policyString5=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:*Delete*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName5, policyString5,200);
        
        String policyString6=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:*List*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName6, policyString6,200);
        
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user2Name, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName3, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user4Name, policyName4, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user5Name, policyName5, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user6Name, policyName6, 200);
        
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 200);
        IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user3accessKey, user3secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user4accessKey, user4secretKey, 200);
        IAMInterfaceTestUtils.ListPolicies(user5accessKey, user5secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user6accessKey, user6secretKey, 403);
        
        // 查看日志 主要看PolicyDocumentCache
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliampolicy
//
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_2
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_2
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy
//        [INFO]( AccessController.java,89 ) [2019-10-10 17:43:27] cn.ctyun.oos.iam.accesscontroller.AccessController - access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::3fdmxmc3pqvmp:policy/*, principal=null, accountId=3fdmxmc3pqvmp, userId=userid2, userName=test_2, currentTime=2019-10-10T09:43:27Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : {"Version":"2012-10-17","Id":"1570700596184","Statement":[{"Sid":"1570700596184_1","Effect":"Allow","Action":"iam:*Group*","Resource":"*"}]}
//
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=098kw0mm2j4p8|test_3
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=098kw0mm2j4p8|test_3
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=098kw0mm2j4p8|alliamuserpolicy
//        [INFO]( AccessController.java,89 ) [2019-10-10 17:43:28] cn.ctyun.oos.iam.accesscontroller.AccessController - access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::098kw0mm2j4p8:policy/*, principal=null, accountId=098kw0mm2j4p8, userId=userid3, userName=test_3, currentTime=2019-10-10T09:43:27Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : {"Version":"2012-10-17","Id":"1570700596486","Statement":[{"Sid":"1570700596486_1","Effect":"Allow","Action":"iam:*User*","Resource":"*"}]}
//
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=098kw0mm2j4p8|test_4
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=098kw0mm2j4p8|test_4
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=098kw0mm2j4p8|alliampolicypolicy
//
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=098kw0mm2j4p8|test_5
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=098kw0mm2j4p8|test_5
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=098kw0mm2j4p8|denydelete
//        [INFO]( AccessController.java,89 ) [2019-10-10 17:43:30] cn.ctyun.oos.iam.accesscontroller.AccessController - access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::098kw0mm2j4p8:policy/*, principal=null, accountId=098kw0mm2j4p8, userId=userid5, userName=test_5, currentTime=2019-10-10T09:43:29Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : {"Version":"2012-10-17","Id":"1570700597260","Statement":[{"Sid":"1570700597260_1","Effect":"Deny","Action":"iam:*Delete*","Resource":"*"}]}
//
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=098kw0mm2j4p8|test_6
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=098kw0mm2j4p8|test_6
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=098kw0mm2j4p8|denylist
//        [ERROR]( AccessController.java,76 ) [2019-10-10 17:43:30] cn.ctyun.oos.iam.accesscontroller.AccessController - access deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::098kw0mm2j4p8:policy/*, principal=null, accountId=098kw0mm2j4p8, userId=userid6, userName=test_6, currentTime=2019-10-10T09:43:30Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : {"Version":"2012-10-17","Id":"1570700597539","Statement":[{"Sid":"1570700597539_1","Effect":"Deny","Action":"iam:*List*","Resource":"*"}]}

        
        IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user3accessKey, user3secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user4accessKey, user4secretKey, 200);
        IAMInterfaceTestUtils.ListPolicies(user5accessKey, user5secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user6accessKey, user6secretKey, 403);
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 200);
        
        // 查看日志
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_2, value=3fdmxmc3pqvmp|alliamgrouppolicy
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy,value={"Version":"2012-10-17","Id":"1570700596184","Statement":[{"Sid":"1570700596184_1","Effect":"Allow","Action":"iam:*Group*","Resource":"*"}]}
//        [INFO]( AccessController.java,89 ) [2019-10-10 17:43:30] cn.ctyun.oos.iam.accesscontroller.AccessController - access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::3fdmxmc3pqvmp:policy/*, principal=null, accountId=3fdmxmc3pqvmp, userId=userid2, userName=test_2, currentTime=2019-10-10T09:43:30Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : {"Version":"2012-10-17","Id":"1570700596184","Statement":[{"Sid":"1570700596184_1","Effect":"Allow","Action":"iam:*Group*","Resource":"*"}]}
//
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=098kw0mm2j4p8|test_3, value=098kw0mm2j4p8|alliamuserpolicy
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=098kw0mm2j4p8|alliamuserpolicy,value={"Version":"2012-10-17","Id":"1570700596486","Statement":[{"Sid":"1570700596486_1","Effect":"Allow","Action":"iam:*User*","Resource":"*"}]}
//        [INFO]( AccessController.java,89 ) [2019-10-10 17:43:30] cn.ctyun.oos.iam.accesscontroller.AccessController - access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::098kw0mm2j4p8:policy/*, principal=null, accountId=098kw0mm2j4p8, userId=userid3, userName=test_3, currentTime=2019-10-10T09:43:30Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : {"Version":"2012-10-17","Id":"1570700596486","Statement":[{"Sid":"1570700596486_1","Effect":"Allow","Action":"iam:*User*","Resource":"*"}]}
//
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=098kw0mm2j4p8|test_4, value=098kw0mm2j4p8|alliampolicypolicy
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=098kw0mm2j4p8|alliampolicypolicy,value={"Version":"2012-10-17","Id":"1570700596961","Statement":[{"Sid":"1570700596961_1","Effect":"Allow","Action":"iam:*Polic*","Resource":"*"}]}
//
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=098kw0mm2j4p8|test_5, value=098kw0mm2j4p8|denydelete
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=098kw0mm2j4p8|denydelete,value={"Version":"2012-10-17","Id":"1570700597260","Statement":[{"Sid":"1570700597260_1","Effect":"Deny","Action":"iam:*Delete*","Resource":"*"}]}
//        [INFO]( AccessController.java,89 ) [2019-10-10 17:43:31] cn.ctyun.oos.iam.accesscontroller.AccessController - access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::098kw0mm2j4p8:policy/*, principal=null, accountId=098kw0mm2j4p8, userId=userid5, userName=test_5, currentTime=2019-10-10T09:43:31Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : {"Version":"2012-10-17","Id":"1570700597260","Statement":[{"Sid":"1570700597260_1","Effect":"Deny","Action":"iam:*Delete*","Resource":"*"}]}
//
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=098kw0mm2j4p8|test_6, value=098kw0mm2j4p8|denylist
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=098kw0mm2j4p8|denylist,value={"Version":"2012-10-17","Id":"1570700597539","Statement":[{"Sid":"1570700597539_1","Effect":"Deny","Action":"iam:*List*","Resource":"*"}]}
//        [ERROR]( AccessController.java,76 ) [2019-10-10 17:43:31] cn.ctyun.oos.iam.accesscontroller.AccessController - access deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::098kw0mm2j4p8:policy/*, principal=null, accountId=098kw0mm2j4p8, userId=userid6, userName=test_6, currentTime=2019-10-10T09:43:31Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : {"Version":"2012-10-17","Id":"1570700597539","Statement":[{"Sid":"1570700597539_1","Effect":"Deny","Action":"iam:*List*","Resource":"*"}]}
//
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliampolicy
    }
    
    @Test
    /*
     * group 附加策略超过5个
     */
    public void test_AttachGroupPolicyKeysCache() {
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString,200);
        
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*User*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName3, policyString3,200);
        
        String policyString4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Polic*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName4, policyString4,200);
        
        String policyString5=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:*Delete*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName5, policyString5,200);
        
        String policyString6=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:*List*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName6, policyString6,200);
        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName1, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName2, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName3, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName4, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName5, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName6, 200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName1, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId1, groupName2, policyName2, 200);


    }
    
    @Test
    /*
     * policyDoc 超过5个
     */
    public void test_PolicyDocumentCache() {
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString,200);
        
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*User*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3,200);
        
        String policyString4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Polic*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName4, policyString4,200);
        
        String policyString5=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:*Delete*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName5, policyString5,200);
        
        String policyString6=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("iam:*List*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName6, policyString6,200);

        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName2, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName3, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName4, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName5, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName6, 200);
        
        
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 403);
        //查看日志
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamuserpolicy
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliampolicypolicy
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliampolicy
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|denydelete
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|denylist
        
        try {
            Thread.sleep(11000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 403);
        // 查看日志
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|alliamgrouppolicy
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|alliampolicy
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|alliampolicypolicy
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|alliamuserpolicy
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|denydelete
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|denylist
//        -----------------list size=6
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------list size=0
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamuserpolicy
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy,value={"Version":"2012-10-17","Id":"1571048116942","Statement":[{"Sid":"1571048116942_1","Effect":"Allow","Action":"iam:*Group*","Resource":"*"}]}
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliampolicypolicy,value={"Version":"2012-10-17","Id":"1571048117470","Statement":[{"Sid":"1571048117470_1","Effect":"Allow","Action":"iam:*Polic*","Resource":"*"}]}
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliampolicy,value={"Version":"2012-10-17","Id":"1571048114609","Statement":[{"Sid":"1571048114609_1","Effect":"Allow","Action":"iam:*","Resource":"*"}]}
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|denydelete,value={"Version":"2012-10-17","Id":"1571048117697","Statement":[{"Sid":"1571048117697_1","Effect":"Deny","Action":"iam:*Delete*","Resource":"*"}]}
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|denylist,value={"Version":"2012-10-17","Id":"1571048117944","Statement":[{"Sid":"1571048117944_1","Effect":"Deny","Action":"iam:*List*","Resource":"*"}]}

    }
    
    @Test
    /*
     * user 附加组然后detach
     */
    public void test_UserGroupKeysCache_Detach() {
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName1, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName2, 200);

        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName1, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName2, user1Name, 200);

        IAMInterfaceTestUtils.ListGroups(user1accessKey, user1secretKey, null,403);
        //查看日志
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|group1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|group2
        
        try {
            Thread.sleep(11000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        IAMInterfaceTestUtils.ListGroups(user1accessKey, user1secretKey, null,403);
        // 查看日志
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|group1
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|group2
//        -----------------list size=2
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------list size=0
        
        IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName1, user1Name, 200);
        try {
            Thread.sleep(11000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        IAMInterfaceTestUtils.ListGroups(user1accessKey, user1secretKey, null,403);
        // 查看日志
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|group2
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------list size=0
        
    }
    
    @Test
    /*
     * user 附加策略然后detach
     */
    public void test_AttachUserPolicyKeysCache_Detach() {
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString,200);
        
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName2, 200);
        
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 200);
      //查看日志
//      -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//      -----------------Key=3fdmxmc3pqvmp|test_1
//      -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//      -----------------Key=3fdmxmc3pqvmp|test_1
//      -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//      -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy
//      -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//      -----------------Key=3fdmxmc3pqvmp|alliampolicy
      
        
        try {
            Thread.sleep(11000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 200);
        // 查看日志
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|alliamgrouppolicy
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|alliampolicy
//        -----------------list size=2
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy,value={"Version":"2012-10-17","Id":"1571043909078","Statement":[{"Sid":"1571043909078_1","Effect":"Allow","Action":"iam:*Group*","Resource":"*"}]}
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliampolicy,value={"Version":"2012-10-17","Id":"1571043908114","Statement":[{"Sid":"1571043908114_1","Effect":"Allow","Action":"iam:*","Resource":"*"}]}

        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        
        try {
            Thread.sleep(11000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 403);
        // 查看日志
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|alliamgrouppolicy
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy,value={"Version":"2012-10-17","Id":"1571043909078","Statement":[{"Sid":"1571043909078_1","Effect":"Allow","Action":"iam:*Group*","Resource":"*"}]}
//        [INFO]( AccessController.java,89 ) [2019-10-14 17:05:34] cn.ctyun.oos.iam.accesscontroller.AccessController - access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::3fdmxmc3pqvmp:policy/*, principal=null, accountId=3fdmxmc3pqvmp, userId=userid1, userName=test_1, currentTime=2019-10-14T09:05:34Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : {"Version":"2012-10-17","Id":"1571043909078","Statement":[{"Sid":"1571043909078_1","Effect":"Allow","Action":"iam:*Group*","Resource":"*"}]}


    }
    
    @Test
    /*
     * group 附加策略然后detach
     */
    public void test_AttachGroupPolicyKeysCache_Detach() {
        
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString,200);
        
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);

        
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName1, 200);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName2, 200);
        
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName1, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName2, 200);

        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName1, user1Name, 200);

        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 200);
        // 查看日志
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|group1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliampolicy
        try {
            Thread.sleep(11000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 200);
        // 查看日志
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|group1
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|group1, value=3fdmxmc3pqvmp|alliamgrouppolicy
//        -----------------Key=3fdmxmc3pqvmp|group1, value=3fdmxmc3pqvmp|alliampolicy
//        -----------------list size=2
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy,value={"Version":"2012-10-17","Id":"1571047193377","Statement":[{"Sid":"1571047193377_1","Effect":"Allow","Action":"iam:*Group*","Resource":"*"}]}
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliampolicy,value={"Version":"2012-10-17","Id":"1571047191129","Statement":[{"Sid":"1571047191129_1","Effect":"Allow","Action":"iam:*","Resource":"*"}]}

        IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName1, 200);
        
        try {
            Thread.sleep(11000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 403);
        // 查看日志
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------list size=0
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|group1
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|group1, value=3fdmxmc3pqvmp|alliamgrouppolicy
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy,value={"Version":"2012-10-17","Id":"1571047193377","Statement":[{"Sid":"1571047193377_1","Effect":"Allow","Action":"iam:*Group*","Resource":"*"}]}
//        [INFO]( AccessController.java,89 ) [2019-10-14 18:00:25] cn.ctyun.oos.iam.accesscontroller.AccessController - access implicit deny, requestInfo : RequestInfo [action=iam:ListPolicies, resource=arn:ctyun:iam::3fdmxmc3pqvmp:policy/*, principal=null, accountId=3fdmxmc3pqvmp, userId=userid1, userName=test_1, currentTime=2019-10-14T10:00:25Z, secureTransport=true, userAgent=Java/1.8.0_92, referer=null, sourceIp=127.0.0.1], polices : {"Version":"2012-10-17","Id":"1571047193377","Statement":[{"Sid":"1571047193377_1","Effect":"Allow","Action":"iam:*Group*","Resource":"*"}]}

    }
    
    @Test
    /*
     * 超过3倍timeout从cache中移除
     */
    public void test_dead() {
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString,200);
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName1, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId1, groupName1, policyName2, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName1, user1Name, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId1, user1Name, policyName1, 200);
        
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*User*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName3, policyString3,200);
        String policyString4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Polic*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey2, secretKey2, policyName4, policyString4,200);
        IAMInterfaceTestUtils.CreateGroup(accessKey2, secretKey2, groupName2, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey2, secretKey2, accountId2, groupName2, policyName4, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey2, secretKey2, groupName2, user3Name, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey2, secretKey2, accountId2, user3Name, policyName3, 200);
        
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 200);
        IAMInterfaceTestUtils.ListPolicies(user3accessKey, user3secretKey, 200);
        // 查看日志
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|group1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliampolicy
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=098kw0mm2j4p8|test_3
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=098kw0mm2j4p8|test_3
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------Key=098kw0mm2j4p8|group2
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=098kw0mm2j4p8|alliamuserpolicy
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=098kw0mm2j4p8|alliampolicypolicy
        try {
            Thread.sleep(11000);
        } catch (Exception e) {
            e.printStackTrace();
        }

        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 200);
        IAMInterfaceTestUtils.ListPolicies(user3accessKey, user3secretKey, 200);
        // 查看日志

//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|alliampolicy
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|group1
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|group1, value=3fdmxmc3pqvmp|alliamgrouppolicy
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy,value={"Version":"2012-10-17","Id":"1571119020973","Statement":[{"Sid":"1571119020973_1","Effect":"Allow","Action":"iam:*Group*","Resource":"*"}]}
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliampolicy,value={"Version":"2012-10-17","Id":"1571119018888","Statement":[{"Sid":"1571119018888_1","Effect":"Allow","Action":"iam:*","Resource":"*"}]}

//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=098kw0mm2j4p8|test_3, value=098kw0mm2j4p8|alliamuserpolicy
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=098kw0mm2j4p8|test_3, value=098kw0mm2j4p8|group2
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------Key=098kw0mm2j4p8|group2, value=098kw0mm2j4p8|alliampolicypolicy
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=098kw0mm2j4p8|alliamuserpolicy,value={"Version":"2012-10-17","Id":"1571119023462","Statement":[{"Sid":"1571119023462_1","Effect":"Allow","Action":"iam:*User*","Resource":"*"}]}
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=098kw0mm2j4p8|alliampolicypolicy,value={"Version":"2012-10-17","Id":"1571119024037","Statement":[{"Sid":"1571119024037_1","Effect":"Allow","Action":"iam:*Polic*","Resource":"*"}]}

        
        
        try {
            Thread.sleep(11000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 200);
        // 查看日志
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|alliampolicy
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1, value=3fdmxmc3pqvmp|group1
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|group1, value=3fdmxmc3pqvmp|alliamgrouppolicy
//        -----------------list size=1
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy,value={"Version":"2012-10-17","Id":"1571119020973","Statement":[{"Sid":"1571119020973_1","Effect":"Allow","Action":"iam:*Group*","Resource":"*"}]}
//        -----------------in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliampolicy,value={"Version":"2012-10-17","Id":"1571119018888","Statement":[{"Sid":"1571119018888_1","Effect":"Allow","Action":"iam:*","Resource":"*"}]}

        
        try {
            Thread.sleep(31000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 200);
        IAMInterfaceTestUtils.ListPolicies(user3accessKey, user3secretKey, 200);
        // 查看日志
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=3fdmxmc3pqvmp|test_1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------Key=3fdmxmc3pqvmp|group1
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliamgrouppolicy
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=3fdmxmc3pqvmp|alliampolicy
        
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachUserPolicyKeysCache
//        -----------------Key=098kw0mm2j4p8|test_3
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.UserGroupKeysCache
//        -----------------Key=098kw0mm2j4p8|test_3
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.AttachGroupPolicyKeysCache
//        -----------------Key=098kw0mm2j4p8|group2
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=098kw0mm2j4p8|alliamuserpolicy
//        -----------------not in IAM cache,cn.ctyun.oos.iam.server.cache.PolicyDocumentCache
//        -----------------Key=098kw0mm2j4p8|alliampolicypolicy
        
    }
    
}
