package cn.ctyun.oos.iam.test.oosaccesscontrol;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.hbase.HBaseRole;
import cn.ctyun.oos.hbase.HBaseUserToRole;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.metadata.RoleMeta;
import cn.ctyun.oos.metadata.UserToRoleMeta;
import cn.ctyun.oos.metadata.UserToTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta;
import cn.ctyun.oos.metadata.RoleMeta.RolePermission;
import cn.ctyun.oos.metadata.VSNTagMeta.VSNTagType;
import common.time.TimeUtils;
import common.tuple.Pair;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ManagementAPIAccessTest {
    
    String HOST="oos-cd.ctyunapi.cn";
    int managementPAIHttpPort=9099;
    int managementPAIHttpsPort=9462;
    
    
    private static String ownerName = "root_user@test.com";
    public static final String accessKey="userak";
    public static final String secretKey="usersk";
    
    public static final String user1Name="test_1";
    public static final String user2Name="test_2";
    public static final String user3Name="Abc1";
    public static final String user1accessKey1="abcdefghijklmnop";
    public static final String user1secretKey1="cccccccccccccccc";
    public static final String user1accessKey2="1234567890123456";
    public static final String user1secretKey2="user1secretKey2lllll";
    public static final String user2accessKey="qrstuvwxyz0000000";
    public static final String user2secretKey="bbbbbbbbbbbbbbbbbb";
    public static final String user3accessKey="abcdefgh12345678";
    public static final String user3secretKey="3333333333333333";
    
    public static String accountId="3rmoqzn03g6ga";
    
    static String today = TimeUtils.toYYYY_MM_dd(new Date());
    
    
    
    public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        CreateUser();
        initTag();
        
    }

    @Before
    public void setUp() throws Exception {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        IAMTestUtils.UpdateUserTable("policy","policyCount");
    }
    
    public static void CreateUser() throws Exception {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);
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
        
        
        String UserName1=user1Name;
        User user1=new User();
        user1.accountId=accountId;
        user1.userName=UserName1;
        user1.userId="test1abc";
        user1.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user1);
            assertTrue(success);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // 插入数据库aksk
        AkSkMeta aksk1 = new AkSkMeta(owner.getId());
        aksk1.isRoot = 0;
        aksk1.userId = user1.userId;
        aksk1.userName = UserName1;
        aksk1.accessKey=user1accessKey1;
        aksk1.setSecretKey(user1secretKey1);
        metaClient.akskInsert(aksk1);
        user1.accessKeys = new ArrayList<>();
        user1.accessKeys.add(aksk1.accessKey);
        
        aksk1.accessKey=user1accessKey2;
        aksk1.setSecretKey(user1secretKey2);
        metaClient.akskInsert(aksk1);
        user1.accessKeys.add(aksk1.accessKey);
        HBaseUtils.put(user1);
        
        String UserName2=user2Name;
        User user2=new User();
        user2.accountId=accountId;
        user2.userName=UserName2;
        user2.userId="Test1Abc";
        user2.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user2);
            assertTrue(success);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        AkSkMeta aksk2 = new AkSkMeta(owner.getId());
        aksk2.isRoot = 0;
        aksk2.userId = user2.userId;
        aksk2.userName = UserName2;
        aksk2.accessKey=user2accessKey;
        aksk2.setSecretKey(user2secretKey);
        metaClient.akskInsert(aksk2);
        user2.accessKeys = new ArrayList<>();
        user2.userName=UserName2;
        user2.accessKeys.add(aksk2.accessKey);
        HBaseUtils.put(user2);
        
        String UserName3=user3Name;
        User user3=new User();
        user3.accountId=accountId;
        user3.userName=UserName3;
        user3.userId="abc1";
        user3.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user3);
            assertTrue(success);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        AkSkMeta aksk3 = new AkSkMeta(owner.getId());
        aksk3.isRoot = 0;
        aksk3.userId = user3.userId;
        aksk3.userName = UserName3;
        aksk3.accessKey=user3accessKey;
        aksk3.setSecretKey(user3secretKey);
        metaClient.akskInsert(aksk3);
        
        user3.accessKeys = new ArrayList<>();
        user3.userName=UserName3;
        user3.accessKeys.add(aksk3.accessKey);
        HBaseUtils.put(user3);   
    }
    
    public static void initTag() throws IOException {
        VSNTagMeta dataTag1;
        VSNTagMeta metaTag1;
        
        
        dataTag1 = new VSNTagMeta("tag1", Arrays.asList(new String[] { "yxregion1","yxregion2"}), VSNTagType.DATA);
        metaClient.vsnTagInsert(dataTag1);
        metaTag1 = new VSNTagMeta("mtag1", Arrays.asList(new String[] { "yxregion1" }), VSNTagType.META);
        metaClient.vsnTagInsert(metaTag1);
        
        UserToTagMeta user2Tag1 = new UserToTagMeta(owner.getId(),
                Arrays.asList(new String[] { dataTag1.getTagName() }), VSNTagType.DATA);
        metaClient.userToTagInsert(user2Tag1);
        UserToTagMeta user2Tag2 = new UserToTagMeta(owner.getId(),
                Arrays.asList(new String[] { metaTag1.getTagName() }), VSNTagType.META);
        metaClient.userToTagInsert(user2Tag2);
        
    }

    @Test
    /*
     * 资源用arn:ctyun:iam::"+accountId+":*
     */
    public void test_GetAccountStatistcsSummary_Allow_Action_ALL() {
        // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Allow_Action_ALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("arn:ctyun:statistics::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        AllowALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1,null);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

    }
    
    @Test
    /*
     * 资源用*
     */
    public void test_GetAccountStatistcsSummary_Allow_Action_ALL2() {
        // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Allow_Action_ALL2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);

        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        AllowALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1,null);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

    }
    

    @Test
    /*
     * 资源用"arn:ctyun:iam::"+accountId+":user/*
     * 资源不匹配不生效
     */
    public void test_GetAccountStatistcsSummary_Allow_Action_Notmath() {
        // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Allow_Action_Notmath";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("arn:ctyun:statistics::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        DenyALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1, null,userName);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

    }
    
    @Test
    /*
     * 资源用"arn:ctyun:iam::"+accountId+":*
     */
    public void test_GetAccountStatistcsSummary_Allow_Action_NotALL() {
        // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Allow_Action_NotALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"NotResource",Arrays.asList("arn:ctyun:statistics::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        DenyALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1, null,userName);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

    }
    
    @Test
    /*
     * 资源用*
     */
    public void test_GetAccountStatistcsSummary_Allow_Action_NotALL2() {
     // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Allow_Action_NotALL2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"NotResource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        DenyALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1, null,userName);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

    }
    
    @Test
    /*
     * 资源用"arn:ctyun:iam::"+accountId+":*
     */
    public void test_GetAccountStatistcsSummary_Allow_NotAction_ALL() {
        // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Allow_NotAction_ALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("arn:ctyun:statistics::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        DenyALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1, null,userName);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

    }
    
    @Test
    /*
     * 资源用*
     */
    public void test_GetAccountStatistcsSummary_Allow_NotAction_ALL2() {
     // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Allow_NotAction_ALL2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        DenyALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1, null,userName);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

    }
    
    @Test
    /*
     * 资源用"arn:ctyun:iam::"+accountId+":*
     */
    public void test_GetAccountStatistcsSummary_Allow_NotAction_NotALL() {
        // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Allow_NotAction_NotALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("statistics:GetAccountStatistcsSummary"),"NotResource",Arrays.asList("arn:ctyun:statistics::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        DenyALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1, null,userName);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

    }
    
    @Test
    /*
     * 资源用*
     */
    public void test_GetAccountStatistcsSummary_Allow_NotAction_NotALL2() {
     // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Allow_NotAction_NotALL2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("statistics:GetAccountStatistcsSummary"),"NotResource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        
        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        DenyALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1, null,userName);
    
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

    }
    
    @Test
    /*
     * 资源用"arn:ctyun:iam::"+accountId+":*
     */
    public void test_GetAccountStatistcsSummary_Deny_Action_ALL() {
        // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Deny_Action_ALL1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_GetAccountStatistcsSummary_Deny_Action_ALL2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("arn:ctyun:statistics::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);

        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        try {
            Thread.sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        DenyALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1, null,userName);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

    }
    
    @Test
    /*
     * 资源用*
     */
    public void test_GetAccountStatistcsSummary_Deny_Action_ALL2() {
        // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Deny_Action_ALL21";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_GetAccountStatistcsSummary_Deny_Action_ALL22";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);

        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        try {
            Thread.sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        DenyALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1, null,userName);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

    }
    

    @Test
    /*
     * 资源用"arn:ctyun:iam::"+accountId+":user/*
     * 资源不匹配不生效
     */
    public void test_GetAccountStatistcsSummary_Deny_Action_Notmath() {
     // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Deny_Action_Notmath1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_GetAccountStatistcsSummary_Deny_Action_Notmath2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);

        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        try {
            Thread.sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        AllowALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1,null);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

    }
    
    @Test
    /*
     * 资源用"arn:ctyun:iam::"+accountId+":*
     */
    public void test_GetAccountStatistcsSummary_Deny_Action_NotALL() {
        // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Deny_Action_NotALL1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_GetAccountStatistcsSummary_Deny_Action_NotALL2";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"NotResource",Arrays.asList("arn:ctyun:statistics::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);

        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        try {
            Thread.sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        AllowALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1,null);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

    }
    
    @Test
    /*
     * 资源用*
     */
    public void test_GetAccountStatistcsSummary_Deny_Action_NotALL2() {
     // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Deny_Action_NotALL21";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_GetAccountStatistcsSummary_Deny_Action_NotALL22";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"NotResource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);

        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        try {
            Thread.sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        AllowALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1,null);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

    }
    
    @Test
    /*
     * 资源用"arn:ctyun:iam::"+accountId+":*
     */
    public void test_GetAccountStatistcsSummary_Deny_NotAction_ALL() {
        // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Deny_Action_NotALL21";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_GetAccountStatistcsSummary_Deny_Action_NotALL22";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("arn:ctyun:statistics::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);

        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        try {
            Thread.sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        AllowALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1,null);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

    }
    
    @Test
    /*
     * 资源用*
     */
    public void test_GetAccountStatistcsSummary_Deny_NotAction_ALL2() {
        // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Deny_Action_NotALL21";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_GetAccountStatistcsSummary_Deny_Action_NotALL22";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);

        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        try {
            Thread.sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        AllowALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1,null);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

    }
    
    @Test
    /*
     * 资源用"arn:ctyun:iam::"+accountId+":*
     */
    public void test_GetAccountStatistcsSummary_Deny_NotAction_NotALL() {
        // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Deny_Action_NotALL21";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_GetAccountStatistcsSummary_Deny_Action_NotALL22";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("statistics:GetAccountStatistcsSummary"),"NotResource",Arrays.asList("arn:ctyun:statistics::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);

        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        try {
            Thread.sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        AllowALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1,null);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

    }
    
    @Test
    /*
     * 资源用*
     */
    public void test_GetAccountStatistcsSummary_Deny_NotAction_NotALL2() {
     // 创建policy
        String policyName="test_GetAccountStatistcsSummary_Deny_Action_NotALL21";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("*"),"Resource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_GetAccountStatistcsSummary_Deny_Action_NotALL22";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("statistics:GetAccountStatistcsSummary"),"NotResource",Arrays.asList("*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);

        
        // 给用户添加policy
        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2,200);
        
        try {
            Thread.sleep(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        AllowALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1,null);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

    }
    
    @Test
    public void test_GetAccountStatistcsSummary_condition_SourceIp() {
        String policyName="test_GetAccountStatistcsSummary_condition_SourceIp";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.168.1.1/24")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("arn:ctyun:statistics::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);

        String userName=user1Name;
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName,200);

        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        List<String> headers1 = Arrays.asList("X-Forwarded-For", "192.168.1.101");
        AllowALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1,headers1);
        
        List<String> headers2 = Arrays.asList("X-Forwarded-For", "192.168.2.101");
        DenyALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1, headers2, userName);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
    }
    
    @Test
    public void test_GetAccountStatistcsSummary_condition_UserName() {
                
        String policyName="test_GetAccountStatistcsSummary_condition_UserName";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("*1*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("arn:ctyun:statistics::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);

        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName,200);
        
        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        AllowALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1,null);
        DenyALLManagementAPI("http",managementPAIHttpPort,user2accessKey, user2secretKey, null, user2Name);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
    }
    
    @Test
    public void test_GetAccountStatistcsSummary_condition_CurrentTime() {
        String policyName="test_GetAccountStatistcsSummary_condition_CurrentTime";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",Arrays.asList("2019-01-01T00:00:00Z")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("arn:ctyun:statistics::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        AllowALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1,null);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
           
    }
    
    @Test
    public void test_GetAccountStatistcsSummary_condition_CurrentTime2() {
        String policyName="test_GetAccountStatistcsSummary_condition_CurrentTime2";

        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList("2019-01-01T00:00:00Z")));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("arn:ctyun:statistics::"+accountId+":*"),conditions2);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
       
        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        DenyALLManagementAPI("http",managementPAIHttpPort,user1accessKey1, user1secretKey1, null, user1Name);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
    }
    
    @Test
    public void test_GetAccountStatistcsSummary_condition_SecureTransport_false() {
        String policyName="test_GetAccountStatistcsSummary_condition_SecureTransport_false";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("false")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("arn:ctyun:statistics::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        DenyALLManagementAPI("https",managementPAIHttpsPort,user1accessKey1, user1secretKey1, null, user1Name);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

    }
    
    @Test
    public void test_GetAccountStatistcsSummary_condition_SecureTransport_true() {
        String policyName="test_GetAccountStatistcsSummary_condition_SecureTransport_true";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("true")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("statistics:GetAccountStatistcsSummary"),"Resource",Arrays.asList("arn:ctyun:statistics::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
          
        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        AllowALLManagementAPI("https",managementPAIHttpsPort,user1accessKey1, user1secretKey1, null);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

    }
    
    
    public void AllowALLManagementAPI(String httpOrHttps,int port,String ak,String sk,List<String> headers) {
        try {
            Pair<Integer, String> getUsage=ManagementAPI_GetUsage(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(200, getUsage.first().intValue());
            assertTrue(getUsage.second().contains("GetUsageResult"));
            
            Pair<Integer, String> getAvailBW=ManagementAPI_GetAvailBW(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(200, getAvailBW.first().intValue());
            assertTrue(getAvailBW.second().contains("GetAvailBWResult"));
            
            Pair<Integer, String> getBandwidth=ManagementAPI_GetBandwidth(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(200, getBandwidth.first().intValue());
            assertTrue(getBandwidth.second().contains("GetBandwidthResult"));
            
            Pair<Integer, String> getConnection=ManagementAPI_GetConnection(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(200, getConnection.first().intValue());
            assertTrue(getConnection.second().contains("GetConnectionResult"));
            
            Pair<Integer, String> getCapacity=ManagementAPI_GetCapacity(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(200, getCapacity.first().intValue());
            assertTrue(getCapacity.second().contains("GetCapacityResponse"));
            
            Pair<Integer, String> getDeleteCapacity=ManagementAPI_GetDeleteCapacity(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(200, getDeleteCapacity.first().intValue());
            assertTrue(getDeleteCapacity.second().contains("GetDeleteCapacityResponse"));
            
            Pair<Integer, String> getTraffics=ManagementAPI_GetTraffics(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(200, getTraffics.first().intValue());
            assertTrue(getTraffics.second().contains("GetTrafficsResponse"));
            
            Pair<Integer, String> getAvailableBandwidth=ManagementAPI_GetAvailableBandwidth(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(200, getAvailableBandwidth.first().intValue());
            assertTrue(getAvailableBandwidth.second().contains("GetAvailableBandwidthResponse"));
            
            Pair<Integer, String> getRequests=ManagementAPI_GetRequests(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(200, getRequests.first().intValue());
            assertTrue(getRequests.second().contains("GetRequestsResponse"));
            
            Pair<Integer, String> getReturnCode=ManagementAPI_GetReturnCode(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(200, getReturnCode.first().intValue());
            assertTrue(getReturnCode.second().contains("GetReturnCodeResponse"));
            
            Pair<Integer, String> getConcurrentConnection=ManagementAPI_GetConcurrentConnection(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(200, getConcurrentConnection.first().intValue());
            assertTrue(getConcurrentConnection.second().contains("GetConcurrentConnectionResponse"));
            
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }
    
   
    public void DenyALLManagementAPI(String httpOrHttps,int port,String ak,String sk,List<String> headers,String username) {
        try {
            Pair<Integer, String> getUsage=ManagementAPI_GetUsage(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(403, getUsage.first().intValue());
            JSONObject getUsageError=IAMTestUtils.ParseErrorToJson(getUsage.second());
            assertEquals("AccessDenied", getUsageError.get("Code"));
            assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+username+" is not authorized to perform: statistics:GetAccountStatistcsSummary on resource: arn:ctyun:statistics::"+accountId+":*.", getUsageError.get("Message"));
            assertEquals("/", getUsageError.get("Resource"));
            
            
            Pair<Integer, String> getAvailBW=ManagementAPI_GetAvailBW(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(403, getAvailBW.first().intValue());
            JSONObject getAvailBWError=IAMTestUtils.ParseErrorToJson(getAvailBW.second());
            assertEquals("AccessDenied", getAvailBWError.get("Code"));
            assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+username+" is not authorized to perform: statistics:GetAccountStatistcsSummary on resource: arn:ctyun:statistics::"+accountId+":*.", getAvailBWError.get("Message"));
            assertEquals("/", getAvailBWError.get("Resource"));

            
            Pair<Integer, String> getBandwidth=ManagementAPI_GetBandwidth(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(403, getBandwidth.first().intValue());
            JSONObject getBandwidthError=IAMTestUtils.ParseErrorToJson(getBandwidth.second());
            assertEquals("AccessDenied", getBandwidthError.get("Code"));
            assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+username+" is not authorized to perform: statistics:GetAccountStatistcsSummary on resource: arn:ctyun:statistics::"+accountId+":*.", getBandwidthError.get("Message"));
            assertEquals("/", getBandwidthError.get("Resource"));

            
            Pair<Integer, String> getConnection=ManagementAPI_GetConnection(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(403, getConnection.first().intValue());
            JSONObject getConnectionError=IAMTestUtils.ParseErrorToJson(getConnection.second());
            assertEquals("AccessDenied", getConnectionError.get("Code"));
            assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+username+" is not authorized to perform: statistics:GetAccountStatistcsSummary on resource: arn:ctyun:statistics::"+accountId+":*.", getConnectionError.get("Message"));
            assertEquals("/", getConnectionError.get("Resource"));
            
            Pair<Integer, String> getCapacity=ManagementAPI_GetCapacity(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(403, getCapacity.first().intValue());
            JSONObject getCapacityError=IAMTestUtils.ParseErrorToJson(getCapacity.second());
            assertEquals("AccessDenied", getCapacityError.get("Code"));
            assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+username+" is not authorized to perform: statistics:GetAccountStatistcsSummary on resource: arn:ctyun:statistics::"+accountId+":*.", getConnectionError.get("Message"));
            assertEquals("/", getCapacityError.get("Resource"));
            
            Pair<Integer, String> getDeleteCapacity=ManagementAPI_GetDeleteCapacity(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(403, getDeleteCapacity.first().intValue());
            JSONObject getDeleteCapacityError=IAMTestUtils.ParseErrorToJson(getDeleteCapacity.second());
            assertEquals("AccessDenied", getDeleteCapacityError.get("Code"));
            assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+username+" is not authorized to perform: statistics:GetAccountStatistcsSummary on resource: arn:ctyun:statistics::"+accountId+":*.", getConnectionError.get("Message"));
            assertEquals("/", getDeleteCapacityError.get("Resource"));
            
            Pair<Integer, String> getTraffics=ManagementAPI_GetTraffics(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(403, getTraffics.first().intValue());
            JSONObject getTrafficsError=IAMTestUtils.ParseErrorToJson(getTraffics.second());
            assertEquals("AccessDenied", getTrafficsError.get("Code"));
            assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+username+" is not authorized to perform: statistics:GetAccountStatistcsSummary on resource: arn:ctyun:statistics::"+accountId+":*.", getConnectionError.get("Message"));
            assertEquals("/", getTrafficsError.get("Resource"));
            
            Pair<Integer, String> getAvailableBandwidth=ManagementAPI_GetAvailableBandwidth(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(403, getAvailableBandwidth.first().intValue());
            JSONObject getAvailableBandwidthError=IAMTestUtils.ParseErrorToJson(getAvailableBandwidth.second());
            assertEquals("AccessDenied", getAvailableBandwidthError.get("Code"));
            assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+username+" is not authorized to perform: statistics:GetAccountStatistcsSummary on resource: arn:ctyun:statistics::"+accountId+":*.", getConnectionError.get("Message"));
            assertEquals("/", getAvailableBandwidthError.get("Resource"));
            
            Pair<Integer, String> getReturnCode=ManagementAPI_GetReturnCode(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(403, getReturnCode.first().intValue());
            JSONObject getReturnCodeError=IAMTestUtils.ParseErrorToJson(getReturnCode.second());
            assertEquals("AccessDenied", getReturnCodeError.get("Code"));
            assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+username+" is not authorized to perform: statistics:GetAccountStatistcsSummary on resource: arn:ctyun:statistics::"+accountId+":*.", getConnectionError.get("Message"));
            assertEquals("/", getReturnCodeError.get("Resource"));
            
            Pair<Integer, String> getConcurrentConnection=ManagementAPI_GetConcurrentConnection(httpOrHttps,port,ak,sk,CreateHeaders(headers));
            assertEquals(403, getConcurrentConnection.first().intValue());
            JSONObject getConcurrentConnectionError=IAMTestUtils.ParseErrorToJson(getConcurrentConnection.second());
            assertEquals("AccessDenied", getConcurrentConnectionError.get("Code"));
            assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+username+" is not authorized to perform: statistics:GetAccountStatistcsSummary on resource: arn:ctyun:statistics::"+accountId+":*.", getConnectionError.get("Message"));
            assertEquals("/", getConcurrentConnectionError.get("Resource"));

            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public Pair<Integer, String> ManagementAPI_GetUsage(String httpOrHttps,int port,String ak,String sk,Map<String, String> headers) throws Exception {
        String Action="GetUsage";
        String beginDate=today;
        String endDate=today;
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, "byDay", null);
        String urlStr = httpOrHttps+"://" + HOST + ":" + port+"/?"+param;

        HttpURLConnection conn=OOSInterfaceTestUtils.CreateConn(urlStr, httpOrHttps, "V2", ak, sk, "GET", null, null, headers, null, null, 80);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Host", HOST + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public Pair<Integer, String> ManagementAPI_GetAvailBW(String httpOrHttps,int port,String ak,String sk,Map<String, String> headers) throws Exception {
        List<String> scope = new ArrayList<String>();
        scope.add("yxregion1");
        addUsrToRole(scope);
        
        String Action="GetAvailBW";
        String beginDate=today+"-00-05";
        String endDate=today+"-08-00";
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, null, null);
        String urlStr = httpOrHttps+"://" + HOST + ":" + port+"/?"+param;

        HttpURLConnection conn=OOSInterfaceTestUtils.CreateConn(urlStr, httpOrHttps, "V2", ak, sk, "GET", null, null, headers, null, null, 80);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Host", HOST + ":" + port);
        
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public Pair<Integer, String> ManagementAPI_GetBandwidth(String httpOrHttps,int port,String ak,String sk,Map<String, String> headers) throws Exception {
        String Action="GetBandwidth";
        String beginDate=today+"-00-05";
        String endDate=today+"-08-00";
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, null, null);
        String urlStr = httpOrHttps+"://" + HOST + ":" + port+"/?"+param;

        HttpURLConnection conn=OOSInterfaceTestUtils.CreateConn(urlStr, httpOrHttps, "V2", ak, sk, "GET", null, null, headers, null, null, 80);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Host", HOST + ":" + port);
        
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public Pair<Integer, String> ManagementAPI_GetConnection(String httpOrHttps,int port,String ak,String sk,Map<String, String> headers) throws Exception {
        String Action="GetConnection";
        String beginDate=today+"-00-05";
        String endDate=today+"-00-10";
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, null, null);
        String urlStr = httpOrHttps+"://" + HOST + ":" + port+"/?"+param;

        HttpURLConnection conn=OOSInterfaceTestUtils.CreateConn(urlStr, httpOrHttps, "V2", ak, sk, "GET", null, null, headers, null, null, 80);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Host", HOST + ":" + port);
        
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public Pair<Integer, String> ManagementAPI_GetCapacity(String httpOrHttps,int port,String ak,String sk,Map<String, String> headers) throws Exception {
        String Action="GetCapacity";
        String beginDate=today;
        String endDate=today;
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, "byDay", null);
        String urlStr = httpOrHttps+"://" + HOST + ":" + port+"/?"+param;

        HttpURLConnection conn=OOSInterfaceTestUtils.CreateConn(urlStr, httpOrHttps, "V2", ak, sk, "GET", null, null, headers, null, null, 80);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Host", HOST + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public Pair<Integer, String> ManagementAPI_GetDeleteCapacity(String httpOrHttps,int port,String ak,String sk,Map<String, String> headers) throws Exception {
        String Action="GetDeleteCapacity";
        String beginDate=today;
        String endDate=today;
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, "byDay", null);
        String urlStr = httpOrHttps+"://" + HOST + ":" + port+"/?"+param;

        HttpURLConnection conn=OOSInterfaceTestUtils.CreateConn(urlStr, httpOrHttps, "V2", ak, sk, "GET", null, null, headers, null, null, 80);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Host", HOST + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public Pair<Integer, String> ManagementAPI_GetTraffics(String httpOrHttps,int port,String ak,String sk,Map<String, String> headers) throws Exception {
        String Action="GetTraffics";
        String beginDate=today;
        String endDate=today;
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, "byDay", null);
        String urlStr = httpOrHttps+"://" + HOST + ":" + port+"/?"+param;

        HttpURLConnection conn=OOSInterfaceTestUtils.CreateConn(urlStr, httpOrHttps, "V2", ak, sk, "GET", null, null, headers, null, null, 80);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Host", HOST + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public Pair<Integer, String> ManagementAPI_GetAvailableBandwidth(String httpOrHttps,int port,String ak,String sk,Map<String, String> headers) throws Exception {
        String Action="GetAvailableBandwidth";
        String beginDate=today;
        String endDate=today;
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, "by5min", null);
        String urlStr = httpOrHttps+"://" + HOST + ":" + port+"/?"+param;

        HttpURLConnection conn=OOSInterfaceTestUtils.CreateConn(urlStr, httpOrHttps, "V2", ak, sk, "GET", null, null, headers, null, null, 80);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Host", HOST + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public Pair<Integer, String> ManagementAPI_GetRequests(String httpOrHttps,int port,String ak,String sk,Map<String, String> headers) throws Exception {
        String Action="GetRequests";
        String beginDate=today;
        String endDate=today;
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, "byDay", null);
        String urlStr = httpOrHttps+"://" + HOST + ":" + port+"/?"+param;

        HttpURLConnection conn=OOSInterfaceTestUtils.CreateConn(urlStr, httpOrHttps, "V2", ak, sk, "GET", null, null, headers, null, null, 80);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Host", HOST + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    public Pair<Integer, String> ManagementAPI_GetReturnCode(String httpOrHttps,int port,String ak,String sk,Map<String, String> headers) throws Exception {
        String Action="GetReturnCode";
        String beginDate=today;
        String endDate=today;
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, "byDay", null);
        String urlStr = httpOrHttps+"://" + HOST + ":" + port+"/?"+param;

        HttpURLConnection conn=OOSInterfaceTestUtils.CreateConn(urlStr, httpOrHttps, "V2", ak, sk, "GET", null, null, headers, null, null, 80);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Host", HOST + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
      
    public Pair<Integer, String> ManagementAPI_GetConcurrentConnection(String httpOrHttps,int port,String ak,String sk,Map<String, String> headers) throws Exception {
        String Action="GetConcurrentConnection";
        String beginDate=today;
        String endDate=today;
        String param = JoinBeginEndDate(Action, beginDate, endDate, null, "by5min", null);
        String urlStr = httpOrHttps+"://" + HOST + ":" + port+"/?"+param;

        HttpURLConnection conn=OOSInterfaceTestUtils.CreateConn(urlStr, httpOrHttps, "V2", ak, sk, "GET", null, null, headers, null, null, 80);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Host", HOST + ":" + port);
        return OOSInterfaceTestUtils.GetResult(conn);
    }
    
    
    public static String JoinBeginEndDate(String Action, String beginDate, String endDate,
            String bucketName, String freq, String pools) {
        StringBuilder sb = new StringBuilder();
        sb.append("Action=").append(Action);
        sb.append("&BeginDate=").append(beginDate).append("&EndDate=").append(endDate);
        if (bucketName!= null) {
            sb.append("&BucketName=").append(bucketName);
        }
        if (freq!=null) {
            sb.append("&Freq=").append(freq);
        }
        if (pools!=null) {
            sb.append("&Pools=").append(pools);
        }
        System.out.println(sb);
        return sb.toString();
    }
    
    public void addUsrToRole(List<String> scope) throws Exception {
        Configuration conf = GlobalHHZConfig.getConfig();
        Configuration globalConf = GlobalHHZConfig.getConfig();
        HBaseAdmin globalHbaseAdmin = new HBaseAdmin(globalConf);
       HBaseRole.dropTable(conf);
       HBaseRole.createTable(globalHbaseAdmin);
       HBaseUserToRole.dropTable(conf);
       HBaseUserToRole.createTable(globalHbaseAdmin);
       globalHbaseAdmin.close();

       Map<RolePermission, List<String>> pools = new TreeMap<>();
       pools.put(RoleMeta.RolePermission.PERMISSION_AVAIL_DATAREGION, scope);
       Map<RolePermission, List<String>> regions = new TreeMap<>();
       regions.put(RoleMeta.RolePermission.PERMISSION_AVAIL_BW, scope);
       RoleMeta role = new RoleMeta("user", "for common use", pools,regions);
       metaClient.roleInsert(role);
       //绑定role
       metaClient.ownerSelect(owner);
       List<Long> roleID = new ArrayList<Long>();
       roleID.add(role.getId());
       UserToRoleMeta userToRole = new UserToRoleMeta(owner.getId(), roleID);
       metaClient.userToRoleInsert(userToRole );
   }
    
    private Map<String, String> CreateHeaders(List<String> propertys) {
        Map<String, String> headers = new HashMap<String, String>();
        if (propertys!=null&&propertys.size()%2==0) {
            int i=0;
            while (i<propertys.size()) {
                headers.put(propertys.get(i), propertys.get(i+1));
                i+=2;
                
            }
        }
        return headers;
    }
}
