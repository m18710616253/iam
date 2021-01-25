package cn.ctyun.oos.iam.test.cloudtrailaccesscontrol;

import static org.junit.Assert.*;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.sun.mail.handlers.image_gif;

import cn.ctyun.oos.hbase.HBaseManageEvent;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.iam.test.oosaccesscontrol.OOSInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.metadata.UserToTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta.VSNTagType;
import common.tuple.Pair;

public class CloudTrailAccessTest {

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
    public static String mygroupName="mygroup";
    public static String bucketName="yx-bucket-2";
    
    
    
    public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {

        IAMTestUtils.TrancateTable("oos-aksk-yx");
        IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);
        createUser();
        initTag();
//        OOSInterfaceTestUtils.Bucket_Put("http", "V2", 80, accessKey, secretKey, bucketName, null, null, null, null, null);
         
    }
    
    public static void createUser() throws Exception {
     // 创建根用户
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
    
    @Before
    public void setUp() throws Exception {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        IAMTestUtils.UpdateUserTable("policy", "policyCount");
        IAMTestUtils.TrancateTable("oos-cloudTrail-yx");
        IAMTestUtils.TrancateTable("oos-manageEvent-yx");
    }
    
    @Test
    public void test_CreateTrail_Allow_Action_trial1() {
        String policyName="test_CreateTrail_Allow_Action_trial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        //testTrail01 可以createTrail
        AllowCreateTrail(ak, sk, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以createTrail
        DenyCreateTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Allow_Action_trailAll() {
        String policyName="test_CreateTrail_Allow_Action_trial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        //testTrail01 可以createTrail
        AllowCreateTrail(ak, sk, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 可以createTrail
        AllowCreateTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Allow_Action_All() {
        String policyName="test_CreateTrail_Allow_Action_All2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        //testTrail01 可以createTrail
        AllowCreateTrail(ak, sk, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 可以createTrail
        AllowCreateTrail(ak, sk, trailName2, null);
    }
    
    
    @Test
    public void test_CreateTrail_Allow_Action_Nottrial1() {
        String policyName="test_CreateTrail_Allow_Action_Nottrial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        //testTrail01 不可以createTrail
        DenyCreateTrail(ak, sk, trailName1, null);
        
        //testTrail02 可以createTrail
        AllowCreateTrail(ak, sk, trailName2, null);

    }
    
    @Test
    public void test_CreateTrail_Allow_Action_NotTrailAll() {
        String policyName="test_CreateTrail_Allow_Action_NotAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不可以createTrail
        DenyCreateTrail(ak, sk, trailName1, null);
        //testTrail02 不可以createTrail
        DenyCreateTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Allow_Action_NotAll() {
        String policyName="test_CreateTrail_Allow_Action_NotAll2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不可以createTrail
        DenyCreateTrail(ak, sk, trailName1, null);
        //testTrail02 不可以createTrail
        DenyCreateTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Allow_Action_ReourceNotMatch() {
        String policyName="test_CreateTrail_Allow_Action_trial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不可以createTrail
        DenyCreateTrail(ak, sk, trailName1, null);
        //testTrail02 不可以createTrail
        DenyCreateTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Allow_NotAction_trial1() {
        String policyName="test_CreateTrail_Allow_Action_trial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不可以createTrail，其他操作可以
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);// 资源不符合，资源为trial/*
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);// 资源不符合，资源为trial/*
        AllowDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以createTrail，其他操作也不可以
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Allow_NotAction_trialAll() {
        String policyName="test_CreateTrail_Allow_NotAction_All";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不可以createTrail，其他操作可以
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以createTrail，其他操作也可以
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Allow_NotAction_All() {
        String policyName="test_CreateTrail_Allow_NotAction_All2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不可以createTrail，其他操作可以
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以createTrail，其他操作也可以
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    
    @Test
    public void test_CreateTrail_Allow_NotAction_Nottrial1() {
        String policyName="test_CreateTrail_Allow_NotAction_Nottrial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不可以createTrail，其他操作也不可以
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);// 资源符合，资源为trial/*
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);// 资源符合，资源为trial/*
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以createTrail，其他操作可以
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Allow_NotAction_NotTrailAll() {
        String policyName="test_CreateTrail_Allow_NotAction_NotAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不可以createTrail，其他操作可以
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以createTrail，其他操作也可以
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Allow_NotAction_NotAll() {
        String policyName="test_CreateTrail_Allow_NotAction_NotAll2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不可以createTrail，其他操作可以
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以createTrail，其他操作也可以
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Deny_Action_trial1() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_CreateTrail_Deny_Action_trial1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        // testTrail01 不可以CreateTrail
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        // testTrail02 可以CreateTrail
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
        
    }
    
    @Test
    public void test_CreateTrail_Deny_Action_trailAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_CreateTrail_Deny_Action_trial1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        // testTrail01 不可以CreateTrail
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        // testTrail02 不可以CreateTrail
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Deny_Action_All() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_CreateTrail_Deny_Action_All2";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        // testTrail01 不可以CreateTrail
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        // testTrail02 不可以CreateTrail
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    
    @Test
    public void test_CreateTrail_Deny_Action_Nottrial1() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_CreateTrail_Deny_Action_trial1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 可以CreateTrail
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        // testTrail02 不可以CreateTrail
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Deny_Action_NotTrailAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_CreateTrail_Deny_Action_NotAll";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 可以CreateTrail 显示拒绝失效
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        // testTrail02 可以CreateTrail 显示拒绝失效
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Deny_Action_NotAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_CreateTrail_Deny_Action_NotAll";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 可以CreateTrail 显示拒绝失效
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        // testTrail02 可以CreateTrail 显示拒绝失效
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Deny_Action_ReourceNotMatch() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_CreateTrail_Deny_Action_NotAll";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail"),"Resource",Arrays.asList("arn:ctyun:cloudtrails::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 可以CreateTrail 资源不匹配
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        // testTrail02 可以CreateTrail 资源不匹配
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Deny_NotAction_trial1() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_CreateTrail_Deny_Action_trial1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        // testTrail01 可以CreateTrail 其他操作不可以
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);// 资源是trail/* 显示拒绝失效
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);// 资源是trail/* 显示拒绝失效
        DenyDeleteTrail(ak, sk, trailName1, null);
        // testTrail02 可以CreateTrail 其他操作可以
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Deny_NotAction_trailAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_CreateTrail_Deny_Action_trial1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        // testTrail01 可以CreateTrail 其他操作不可以
        AllowCreateTrail(ak, sk, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        // testTrail02 可以CreateTrail 其他操作可以
        AllowCreateTrail(ak, sk, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Deny_NotAction_All() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_CreateTrail_Deny_Action_trial1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        // testTrail01 可以CreateTrail 其他操作不可以
        AllowCreateTrail(ak, sk, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        // testTrail02 可以CreateTrail 其他操作可以
        AllowCreateTrail(ak, sk, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    
    @Test
    public void test_CreateTrail_Deny_NotAction_Nottrial1() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_CreateTrail_Deny_NotAction_Nottrial1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        // testTrail01 可以CreateTrail 其他操作不可以
        AllowCreateTrail(ak, sk, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        // testTrail02 可以CreateTrail 其他操作可以
        AllowCreateTrail(ak, sk, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Deny_NotAction_NotTrailAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_CreateTrail_Deny_NotAction_NotAll";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        // testTrail01 可以CreateTrail 
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null); 
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        // testTrail02 可以CreateTrail 
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_CreateTrail_Deny_NotAction_NotAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_CreateTrail_Deny_NotAction_NotAll";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        // testTrail01 可以CreateTrail 其他操作不可以
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null); 
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        // testTrail02 可以CreateTrail 其他操作可以
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_DescribeTrails_Allow_Action_ReourceNotMath() {
        String policyName="test_AllMethod_Allow_Action_trial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:DescribeTrails"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        AllowCreateTrail(accessKey, secretKey, trailName, null);
        DenyDescribeTrails(ak, sk, trailName, null);
    }
    
    @Test
    public void test_DescribeTrails_Allow_Action_trailAll() {
        String policyName="test_AllMethod_Allow_Action_trial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:DescribeTrails"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        AllowCreateTrail(accessKey, secretKey, trailName, null);
        AllowDescribeTrails(ak, sk, trailName, null);
    }
    
    @Test
    public void test_DescribeTrails_Allow_Action_All() {
        String policyName="test_DescribeTrails_Allow_Action_All";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:DescribeTrails"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        AllowCreateTrail(accessKey, secretKey, trailName, null);
        AllowDescribeTrails(ak, sk, trailName, null);
    }
         
    @Test
    public void test_DescribeTrails_Allow_Action_NotTrailAll() {
        String policyName="test_DescribeTrails_Allow_Action_NotTrailAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:DescribeTrails"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        AllowCreateTrail(accessKey, secretKey, trailName, null);
        DenyDescribeTrails(ak, sk, trailName, null);
    }
    
    @Test
    public void test_DescribeTrails_Allow_Action_NotAll() {
        String policyName="test_DescribeTrails_Allow_Action_NotAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:DescribeTrails"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        AllowCreateTrail(accessKey, secretKey, trailName, null);
        DenyDescribeTrails(ak, sk, trailName, null);
    }
    
    
    @Test
    public void test_DescribeTrails_Allow_NotAction_trailAll() {
        String policyName="test_DescribeTrails_Allow_NotAction_trailAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:DescribeTrails"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        AllowCreateTrail(ak, sk, trailName, null);
        DenyDescribeTrails(ak, sk, trailName, null);
        AllowGetTrailStatus(ak, sk, trailName, null);
        AllowPutEventSelectors(ak, sk, trailName, null);
        AllowGetEventSelectors(ak, sk, trailName, null);
        AllowStartLogging(ak, sk, trailName, null);
        AllowStopLogging(ak, sk, trailName, null);
        AllowUpdateTrail(ak, sk, trailName, null);
        AllowLookupEvents(ak, sk, trailName, null);
        AllowDeleteTrail(ak, sk, trailName, null);
    }
    
    @Test
    public void test_DescribeTrails_Allow_NotAction_All() {
        String policyName="test_DescribeTrails_Allow_NotAction_All";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:DescribeTrails"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        AllowCreateTrail(ak, sk, trailName, null);
        DenyDescribeTrails(ak, sk, trailName, null);
        AllowGetTrailStatus(ak, sk, trailName, null);
        AllowPutEventSelectors(ak, sk, trailName, null);
        AllowGetEventSelectors(ak, sk, trailName, null);
        AllowStartLogging(ak, sk, trailName, null);
        AllowStopLogging(ak, sk, trailName, null);
        AllowUpdateTrail(ak, sk, trailName, null);
        AllowLookupEvents(ak, sk, trailName, null);
        AllowDeleteTrail(ak, sk, trailName, null);
    }
  
    
    @Test
    public void test_DescribeTrails_Allow_NotAction_NottrialAll() {
        String policyName="test_DescribeTrails_Allow_NotAction_NottrialAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:DescribeTrails"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        DenyCreateTrail(ak, sk, trailName, null);
        AllowCreateTrail(accessKey, secretKey, trailName, null);
        DenyDescribeTrails(ak, sk, trailName, null);
        DenyGetTrailStatus(ak, sk, trailName, null);
        DenyPutEventSelectors(ak, sk, trailName, null);
        DenyGetEventSelectors(ak, sk, trailName, null);
        DenyStartLogging(ak, sk, trailName, null);
        DenyStopLogging(ak, sk, trailName, null);
        DenyUpdateTrail(ak, sk, trailName, null);
        DenyLookupEvents(ak, sk, trailName, null);
        DenyDeleteTrail(ak, sk, trailName, null);
    }
    
    @Test
    public void test_DescribeTrails_Allow_NotAction_NotAll() {
        String policyName="test_DescribeTrails_Allow_NotAction_NottrialAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:DescribeTrails"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        DenyCreateTrail(ak, sk, trailName, null);
        AllowCreateTrail(accessKey, secretKey, trailName, null);
        DenyDescribeTrails(ak, sk, trailName, null);
        DenyGetTrailStatus(ak, sk, trailName, null);
        DenyPutEventSelectors(ak, sk, trailName, null);
        DenyGetEventSelectors(ak, sk, trailName, null);
        DenyStartLogging(ak, sk, trailName, null);
        DenyStopLogging(ak, sk, trailName, null);
        DenyUpdateTrail(ak, sk, trailName, null);
        DenyLookupEvents(ak, sk, trailName, null);
        DenyDeleteTrail(ak, sk, trailName, null);
    }
    
    @Test
    public void test_DescribeTrails_Deny_Action_ReourceNotMatch() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_DescribeTrails_Deny_Action_ReourceNotMatch";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:DescribeTrails"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        AllowCreateTrail(ak, sk, trailName, null);
        AllowDescribeTrails(ak, sk, trailName, null);
    }
    
    @Test
    public void test_DescribeTrails_Deny_Action_trialAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_DescribeTrails_Deny_Action_trialAll";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:DescribeTrails"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        AllowCreateTrail(ak, sk, trailName, null);
        DenyDescribeTrails(ak, sk, trailName, null);
    }
    
    @Test
    public void test_DescribeTrails_Deny_Action_All() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_DescribeTrails_Deny_Action_All";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:DescribeTrails"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        AllowCreateTrail(ak, sk, trailName, null);
        DenyDescribeTrails(ak, sk, trailName, null);
    }
    
    
    @Test
    public void test_DescribeTrails_Deny_Action_NotTrailAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_DescribeTrails_Deny_Action_NotTrailAll";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:DescribeTrails"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        AllowCreateTrail(ak, sk, trailName, null);
        AllowDescribeTrails(ak, sk, trailName, null);
    }
    
    @Test
    public void test_DescribeTrails_Deny_Action_NotAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_DescribeTrails_Deny_Action_NotTrailAll";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:DescribeTrails"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        AllowCreateTrail(ak, sk, trailName, null);
        AllowDescribeTrails(ak, sk, trailName, null);
    }
    
    @Test
    public void test_DescribeTrails_Deny_NotAction_trialAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_DescribeTrails_Deny_Action_ReourceNotMatch";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:DescribeTrails"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        
        DenyCreateTrail(ak, sk, trailName, null);
        AllowCreateTrail(accessKey, secretKey, trailName, null);
        AllowDescribeTrails(ak, sk, trailName, null);
        DenyGetTrailStatus(ak, sk, trailName, null);
        DenyPutEventSelectors(ak, sk, trailName, null);
        DenyGetEventSelectors(ak, sk, trailName, null);
        DenyStartLogging(ak, sk, trailName, null);
        DenyStopLogging(ak, sk, trailName, null);
        DenyUpdateTrail(ak, sk, trailName, null);
        DenyLookupEvents(ak, sk, trailName, null);
        DenyDeleteTrail(ak, sk, trailName, null);
    }
    
    @Test
    public void test_DescribeTrails_Deny_NotAction_All() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_DescribeTrails_Deny_Action_ReourceNotMatch";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:DescribeTrails"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        
        DenyCreateTrail(ak, sk, trailName, null);
        AllowCreateTrail(accessKey, secretKey, trailName, null);
        AllowDescribeTrails(ak, sk, trailName, null);
        DenyGetTrailStatus(ak, sk, trailName, null);
        DenyPutEventSelectors(ak, sk, trailName, null);
        DenyGetEventSelectors(ak, sk, trailName, null);
        DenyStartLogging(ak, sk, trailName, null);
        DenyStopLogging(ak, sk, trailName, null);
        DenyUpdateTrail(ak, sk, trailName, null);
        DenyLookupEvents(ak, sk, trailName, null);
        DenyDeleteTrail(ak, sk, trailName, null);
    }
    
    
    @Test
    public void test_DescribeTrails_Deny_NotAction_NotTrailAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        System.out.println(policyString);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_DescribeTrails_Deny_Action_ReourceNotMatch";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:DescribeTrails"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        System.out.println(policyString1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        
        AllowCreateTrail(ak, sk, trailName, null);
        AllowDescribeTrails(ak, sk, trailName, null);
        AllowGetTrailStatus(ak, sk, trailName, null);
        AllowPutEventSelectors(ak, sk, trailName, null);
        AllowGetEventSelectors(ak, sk, trailName, null);
        AllowStartLogging(ak, sk, trailName, null);
        AllowStopLogging(ak, sk, trailName, null);
        AllowUpdateTrail(ak, sk, trailName, null);
        AllowLookupEvents(ak, sk, trailName, null);
        AllowDeleteTrail(ak, sk, trailName, null);
    }
    
    @Test
    public void test_DescribeTrails_Deny_NotAction_NotAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        System.out.println(policyString);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String policyName1="test_DescribeTrails_Deny_Action_ReourceNotMatch";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:DescribeTrails"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        System.out.println(policyString1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        String trailName="testTrail01";
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        
        AllowCreateTrail(ak, sk, trailName, null);
        AllowDescribeTrails(ak, sk, trailName, null);
        AllowGetTrailStatus(ak, sk, trailName, null);
        AllowPutEventSelectors(ak, sk, trailName, null);
        AllowGetEventSelectors(ak, sk, trailName, null);
        AllowStartLogging(ak, sk, trailName, null);
        AllowStopLogging(ak, sk, trailName, null);
        AllowUpdateTrail(ak, sk, trailName, null);
        AllowLookupEvents(ak, sk, trailName, null);
        AllowDeleteTrail(ak, sk, trailName, null);
    }
    
    @Test
    public void test_AllMethod_Allow_Action_trial1() {
        String policyName="test_AllMethod_Allow_Action_trial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        //testTrail01 可以除了DescribeTrails，LookupEvents
        AllowCreateTrail(ak, sk, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以所有操作
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Allow_Action_trailAll() {
        String policyName="test_AllMethod_Allow_Action_trailAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        //testTrail01 可以所有操作
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 可以所有操作
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Allow_Action_All() {
        String policyName="test_AllMethod_Allow_Action_All";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        //testTrail01 可以所有操作
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 可以所有操作
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    
    @Test
    public void test_AllMethod_Allow_Action_Nottrial1() {
        String policyName="test_AllMethod_Allow_Action_trial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";

        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
         
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Allow_Action_NotTrailAll() {
        String policyName="test_AllMethod_Allow_Action_trial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";

        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
         
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Allow_Action_NotAll() {
        String policyName="test_AllMethod_Allow_Action_trial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";

        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
         
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Allow_Action_ReourceNotMatch() {
        String policyName="test_AllMethod_Allow_Action_trial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrails::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        //testTrail01 不可以所有操作
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以所有操作
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Allow_NotAction_trial1() {
        String policyName="test_AllMethod_Allow_Action_trial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        //testTrail01 不可以所有操作
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以所有操作
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Allow_NotAction_trailAll() {
        String policyName="test_AllMethod_Allow_NotAction_trailAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        //testTrail01 不可以所有操作
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以所有操作
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Allow_NotAction_All() {
        String policyName="test_AllMethod_Allow_NotAction_trailAll";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        //testTrail01 不可以所有操作
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以所有操作
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    
    @Test
    public void test_AllMethod_Allow_NotAction_Nottrial1() {
        String policyName="test_AllMethod_Allow_NotAction_Nottrial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        //testTrail01 不可以所有操作
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以所有操作
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Allow_NotAction_NottrialAll() {
        String policyName="test_AllMethod_Allow_NotAction_Nottrial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        //testTrail01 不可以所有操作
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以所有操作
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Allow_NotAction_NotAll() {
        String policyName="test_AllMethod_Allow_NotAction_Nottrial1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        //testTrail01 不可以所有操作
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不可以所有操作
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Deny_Action_trial1() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
      
        String policyName1="test_AllMethod_Deny_Action_trial1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 拒绝
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不拒绝
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Deny_Action_trialAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
      
        String policyName1="test_AllMethod_Deny_Action_trial1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 拒绝
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 拒绝
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Deny_Action_All() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
      
        String policyName1="test_AllMethod_Deny_Action_All";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 拒绝
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 拒绝
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    
    @Test
    public void test_AllMethod_Deny_Action_Nottrial1() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
      
        String policyName1="test_AllMethod_Deny_Action_Nottrial1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不拒绝
        AllowCreateTrail(ak, sk, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null); 
        //testTrail02 拒绝
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Deny_Action_NotTrailAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
      
        String policyName1="test_AllMethod_Deny_Action_trial1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不拒绝
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        
        //testTrail02 不拒绝
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Deny_Action_NotAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
      
        String policyName1="test_AllMethod_Deny_Action_NotAll";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不拒绝
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        
        //testTrail02 不拒绝
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Deny_Action_ReourceNotMatch() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
      
        String policyName1="test_AllMethod_Deny_Action_trial1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrails::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不拒绝
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不拒绝
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Deny_NotAction_trial1() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
      
        String policyName1="test_AllMethod_Deny_NotAction_trial1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不拒绝
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不拒绝
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Deny_NotAction_trialAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
      
        String policyName1="test_AllMethod_Deny_NotAction_trialAll";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不拒绝
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不拒绝
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Deny_NotAction_All() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
      
        String policyName1="test_AllMethod_Deny_NotAction_trialAll";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不拒绝
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不拒绝
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    
    @Test
    public void test_AllMethod_Deny_NotAction_Nottrial1() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
      
        String policyName1="test_AllMethod_Deny_NotAction_trial1";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/testTrail01"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不拒绝
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不拒绝
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Deny_NotAction_NotTrailAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
      
        String policyName1="test_AllMethod_Deny_NotAction_NotTrailAll";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不拒绝
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不拒绝
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Deny_NotAction_NotAll() {
        String policyName="AllowALL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
      
        String policyName1="test_AllMethod_Deny_NotAction_trialAll";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"NotAction",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"NotResource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        //testTrail01 不拒绝
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        //testTrail02 不拒绝
        AllowCreateTrail(ak, sk, trailName2, null);
        AllowDescribeTrails(ak, sk, trailName2, null);
        AllowGetTrailStatus(ak, sk, trailName2, null);
        AllowPutEventSelectors(ak, sk, trailName2, null);
        AllowGetEventSelectors(ak, sk, trailName2, null);
        AllowStartLogging(ak, sk, trailName2, null);
        AllowStopLogging(ak, sk, trailName2, null);
        AllowUpdateTrail(ak, sk, trailName2, null);
        AllowLookupEvents(ak, sk, trailName2, null);
        AllowDeleteTrail(ak, sk, trailName2, null);
    }
    
    @Test
    public void test_AllMethod_Condition_sourceIP() {
        String policyName="test_AllMethod_Condition_sourceIP";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),conditions);     
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        String trailName3="testTrail03";
        
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        
        List<String> ips1= Arrays.asList("X-Forwarded-For","192.168.2.101");
        DenyCreateTrail(ak, sk, trailName2, CreateHeaders(ips1));
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, CreateHeaders(ips1));
        DenyGetTrailStatus(ak, sk, trailName2, CreateHeaders(ips1));
        DenyPutEventSelectors(ak, sk, trailName2, CreateHeaders(ips1));
        DenyGetEventSelectors(ak, sk, trailName2, CreateHeaders(ips1));
        DenyStartLogging(ak, sk, trailName2, CreateHeaders(ips1));
        DenyStopLogging(ak, sk, trailName2, CreateHeaders(ips1));
        DenyUpdateTrail(ak, sk, trailName2, CreateHeaders(ips1));
        DenyLookupEvents(ak, sk, trailName2, CreateHeaders(ips1));
        DenyDeleteTrail(ak, sk, trailName2, CreateHeaders(ips1));
        
        List<String> ips2= Arrays.asList("X-Forwarded-For","192.168.1.101");
        AllowCreateTrail(ak, sk, trailName3, CreateHeaders(ips2));
        AllowDescribeTrails(ak, sk, trailName3, CreateHeaders(ips2));
        AllowGetTrailStatus(ak, sk, trailName3, CreateHeaders(ips2));
        AllowPutEventSelectors(ak, sk, trailName3, CreateHeaders(ips2));
        AllowGetEventSelectors(ak, sk, trailName3, CreateHeaders(ips2));
        AllowStartLogging(ak, sk, trailName3, CreateHeaders(ips2));
        AllowStopLogging(ak, sk, trailName3, CreateHeaders(ips2));
        AllowUpdateTrail(ak, sk, trailName3, CreateHeaders(ips2));
        AllowLookupEvents(ak, sk, trailName3, CreateHeaders(ips2));
        AllowDeleteTrail(ak, sk, trailName3, CreateHeaders(ips2));
        
        
    }
    
    @Test
    public void test_AllMethod_Condition_UserAgent() {
        String policyName="test_AllMethod_Condition_UserAgent";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:UserAgent",Arrays.asList("Java/1.8.0")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),conditions);     
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        String trailName3="testTrail03";
        
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        
        List<String> ips1= Arrays.asList("User-Agent","Java/1.8.0_91");
        DenyCreateTrail(ak, sk, trailName2, CreateHeaders(ips1));
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, CreateHeaders(ips1));
        DenyGetTrailStatus(ak, sk, trailName2, CreateHeaders(ips1));
        DenyPutEventSelectors(ak, sk, trailName2, CreateHeaders(ips1));
        DenyGetEventSelectors(ak, sk, trailName2, CreateHeaders(ips1));
        DenyStartLogging(ak, sk, trailName2, CreateHeaders(ips1));
        DenyStopLogging(ak, sk, trailName2, CreateHeaders(ips1));
        DenyUpdateTrail(ak, sk, trailName2, CreateHeaders(ips1));
        DenyLookupEvents(ak, sk, trailName2, CreateHeaders(ips1));
        DenyDeleteTrail(ak, sk, trailName2, CreateHeaders(ips1));
        
        List<String> ips2= Arrays.asList("User-Agent","Java/1.8.0");
        AllowCreateTrail(ak, sk, trailName3, CreateHeaders(ips2));
        AllowDescribeTrails(ak, sk, trailName3, CreateHeaders(ips2));
        AllowGetTrailStatus(ak, sk, trailName3, CreateHeaders(ips2));
        AllowPutEventSelectors(ak, sk, trailName3, CreateHeaders(ips2));
        AllowGetEventSelectors(ak, sk, trailName3, CreateHeaders(ips2));
        AllowStartLogging(ak, sk, trailName3, CreateHeaders(ips2));
        AllowStopLogging(ak, sk, trailName3, CreateHeaders(ips2));
        AllowUpdateTrail(ak, sk, trailName3, CreateHeaders(ips2));
        AllowLookupEvents(ak, sk, trailName3, CreateHeaders(ips2));
        AllowDeleteTrail(ak, sk, trailName3, CreateHeaders(ips2));

    }
    
    @Test
    public void test_AllMethod_Condition_Referer() {
        String policyName="test_AllMethod_Condition_Referer";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:Referer",Arrays.asList("http://www.yourwebsitename.com/login.html")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),conditions);     
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        String trailName3="testTrail03";
        
        DenyCreateTrail(ak, sk, trailName1, null);
        AllowCreateTrail(accessKey, secretKey, trailName1, null);
        DenyDescribeTrails(ak, sk, trailName1, null);
        DenyGetTrailStatus(ak, sk, trailName1, null);
        DenyPutEventSelectors(ak, sk, trailName1, null);
        DenyGetEventSelectors(ak, sk, trailName1, null);
        DenyStartLogging(ak, sk, trailName1, null);
        DenyStopLogging(ak, sk, trailName1, null);
        DenyUpdateTrail(ak, sk, trailName1, null);
        DenyLookupEvents(ak, sk, trailName1, null);
        DenyDeleteTrail(ak, sk, trailName1, null);
        
        List<String> ips1= Arrays.asList("Referer","http://www.yourwebsitename.com/login.html");
        DenyCreateTrail(ak, sk, trailName2, CreateHeaders(ips1));
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, CreateHeaders(ips1));
        DenyGetTrailStatus(ak, sk, trailName2, CreateHeaders(ips1));
        DenyPutEventSelectors(ak, sk, trailName2, CreateHeaders(ips1));
        DenyGetEventSelectors(ak, sk, trailName2, CreateHeaders(ips1));
        DenyStartLogging(ak, sk, trailName2, CreateHeaders(ips1));
        DenyStopLogging(ak, sk, trailName2, CreateHeaders(ips1));
        DenyUpdateTrail(ak, sk, trailName2, CreateHeaders(ips1));
        DenyLookupEvents(ak, sk, trailName2, CreateHeaders(ips1));
        DenyDeleteTrail(ak, sk, trailName2, CreateHeaders(ips1));
        
        List<String> ips2= Arrays.asList("Referer","http://www.yourwebsitename.com/console.html");
        AllowCreateTrail(ak, sk, trailName3, CreateHeaders(ips2));
        AllowDescribeTrails(ak, sk, trailName3, CreateHeaders(ips2));
        AllowGetTrailStatus(ak, sk, trailName3, CreateHeaders(ips2));
        AllowPutEventSelectors(ak, sk, trailName3, CreateHeaders(ips2));
        AllowGetEventSelectors(ak, sk, trailName3, CreateHeaders(ips2));
        AllowStartLogging(ak, sk, trailName3, CreateHeaders(ips2));
        AllowStopLogging(ak, sk, trailName3, CreateHeaders(ips2));
        AllowUpdateTrail(ak, sk, trailName3, CreateHeaders(ips2));
        AllowLookupEvents(ak, sk, trailName3, CreateHeaders(ips2));
        AllowDeleteTrail(ak, sk, trailName3, CreateHeaders(ips2));
     
    }
    
    @Test
    public void test_AllMethod_Condition_username() {
        String policyName="test_AllMethod_Condition_username";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:CreateTrail","cloudtrail:DeleteTrail","cloudtrail:GetTrailStatus","cloudtrail:PutEventSelectors","cloudtrail:GetEventSelectors","cloudtrail:UpdateTrail","cloudtrail:StartLogging","cloudtrail:StopLogging","cloudtrail:DescribeTrails","cloudtrail:LookupEvents"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),conditions);     
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName, 200);
        
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        String trailName3="testTrail03";
        
        AllowCreateTrail(user1accessKey1, user1secretKey1, trailName1, null);
        AllowDescribeTrails(user1accessKey1, user1secretKey1, trailName1, null);
        AllowGetTrailStatus(user1accessKey1, user1secretKey1, trailName1, null);
        AllowPutEventSelectors(user1accessKey1, user1secretKey1, trailName1, null);
        AllowGetEventSelectors(user1accessKey1, user1secretKey1, trailName1, null);
        AllowStartLogging(user1accessKey1, user1secretKey1, trailName1, null);
        AllowStopLogging(user1accessKey1, user1secretKey1, trailName1, null);
        AllowUpdateTrail(user1accessKey1, user1secretKey1, trailName1, null);
        AllowLookupEvents(user1accessKey1, user1secretKey1, trailName1, null);
        AllowDeleteTrail(user1accessKey1, user1secretKey1, trailName1, null);
        
        AllowCreateTrail(user2accessKey, user2secretKey, trailName2, null);
        AllowDescribeTrails(user2accessKey, user2secretKey, trailName2, null);
        AllowGetTrailStatus(user2accessKey, user2secretKey, trailName2, null);
        AllowPutEventSelectors(user2accessKey, user2secretKey, trailName2, null);
        AllowGetEventSelectors(user2accessKey, user2secretKey, trailName2, null);
        AllowStartLogging(user2accessKey, user2secretKey, trailName2, null);
        AllowStopLogging(user2accessKey, user2secretKey, trailName2, null);
        AllowUpdateTrail(user2accessKey, user2secretKey, trailName2, null);
        AllowLookupEvents(user2accessKey, user2secretKey, trailName2, null);
        AllowDeleteTrail(user2accessKey, user2secretKey, trailName2, null);
        
        DenyCreateTrail(user3accessKey, user3secretKey, trailName3, null);
        DenyDescribeTrails(user3accessKey, user3secretKey, trailName3, null);
        DenyGetTrailStatus(user3accessKey, user3secretKey, trailName3, null);
        DenyPutEventSelectors(user3accessKey, user3secretKey, trailName3, null);
        DenyGetEventSelectors(user3accessKey, user3secretKey, trailName3, null);
        DenyStartLogging(user3accessKey, user3secretKey, trailName3, null);
        DenyStopLogging(user3accessKey, user3secretKey, trailName3, null);
        DenyUpdateTrail(user3accessKey, user3secretKey, trailName3, null);
        DenyLookupEvents(user3accessKey, user3secretKey, trailName3, null);
        DenyDeleteTrail(user3accessKey, user3secretKey, trailName3, null);
        
    }
    
    @Test
    public void test_AllMethod_Condition_CurrentTime() {
        String yesterdayString=OneDay0UTCTimeString(-1);
        String todyString=OneDay0UTCTimeString(0);
        String tomorrowString=OneDay0UTCTimeString(1);
        
        String policyName1="CurrentTime_DateLessThanEquals_Allow";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("DateLessThanEquals","ctyun:CurrentTime",Arrays.asList(tomorrowString)));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),conditions1);     
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        
        String policyName2="CurrentTime_DateLessThanEquals_Allow2";
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("DateLessThanEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),conditions2); 
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
        
        String policyName3="CurrentTime_DateLessThanEquals_Allow3";
        List<Condition> conditions3 = new ArrayList<Condition>();
        conditions3.add(IAMTestUtils.CreateCondition("DateLessThanEquals","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
        String policyString3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),conditions3); 
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
        
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        String trailName3="testTrail03";
        
        AllowCreateTrail(user1accessKey1, user1secretKey1, trailName1, null);
        AllowDescribeTrails(user1accessKey1, user1secretKey1, trailName1, null);
        AllowGetTrailStatus(user1accessKey1, user1secretKey1, trailName1, null);
        AllowPutEventSelectors(user1accessKey1, user1secretKey1, trailName1, null);
        AllowGetEventSelectors(user1accessKey1, user1secretKey1, trailName1, null);
        AllowStartLogging(user1accessKey1, user1secretKey1, trailName1, null);
        AllowStopLogging(user1accessKey1, user1secretKey1, trailName1, null);
        AllowUpdateTrail(user1accessKey1, user1secretKey1, trailName1, null);
        AllowLookupEvents(user1accessKey1, user1secretKey1, trailName1, null);
        AllowDeleteTrail(user1accessKey1, user1secretKey1, trailName1, null);
        
        DenyCreateTrail(user2accessKey, user2secretKey, trailName2, null);
        DenyDescribeTrails(user2accessKey, user2secretKey, trailName2, null);
        DenyGetTrailStatus(user2accessKey, user2secretKey, trailName2, null);
        DenyPutEventSelectors(user2accessKey, user2secretKey, trailName2, null);
        DenyGetEventSelectors(user2accessKey, user2secretKey, trailName2, null);
        DenyStartLogging(user2accessKey, user2secretKey, trailName2, null);
        DenyStopLogging(user2accessKey, user2secretKey, trailName2, null);
        DenyUpdateTrail(user2accessKey, user2secretKey, trailName2, null);
        DenyLookupEvents(user2accessKey, user2secretKey, trailName2, null);
        DenyDeleteTrail(user2accessKey, user2secretKey, trailName2, null);
        
        DenyCreateTrail(user3accessKey, user3secretKey, trailName3, null);
        DenyDescribeTrails(user3accessKey, user3secretKey, trailName3, null);
        DenyGetTrailStatus(user3accessKey, user3secretKey, trailName3, null);
        DenyPutEventSelectors(user3accessKey, user3secretKey, trailName3, null);
        DenyGetEventSelectors(user3accessKey, user3secretKey, trailName3, null);
        DenyStartLogging(user3accessKey, user3secretKey, trailName3, null);
        DenyStopLogging(user3accessKey, user3secretKey, trailName3, null);
        DenyUpdateTrail(user3accessKey, user3secretKey, trailName3, null);
        DenyLookupEvents(user3accessKey, user3secretKey, trailName3, null);
        DenyDeleteTrail(user3accessKey, user3secretKey, trailName3, null);

    }

    @Test
    public void test_AllMethod_Condition_SecureTransport() {
        String policyName="allow_ssL";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),null);     
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String ak=user1accessKey1;
        String sk=user1secretKey1;
        String trailName1="testTrail01";
        String trailName2="testTrail02";
        
        AllowCreateTrail(ak, sk, trailName1, null);
        AllowDescribeTrails(ak, sk, trailName1, null);
        AllowGetTrailStatus(ak, sk, trailName1, null);
        AllowPutEventSelectors(ak, sk, trailName1, null);
        AllowGetEventSelectors(ak, sk, trailName1, null);
        AllowStartLogging(ak, sk, trailName1, null);
        AllowStopLogging(ak, sk, trailName1, null);
        AllowUpdateTrail(ak, sk, trailName1, null);
        AllowLookupEvents(ak, sk, trailName1, null);
        AllowDeleteTrail(ak, sk, trailName1, null);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        try {
            Thread.sleep(10000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        String policyName1="not_allow_ssL";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("false")));
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/*"),conditions);     
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        
        DenyCreateTrail(ak, sk, trailName2, null);
        AllowCreateTrail(accessKey, secretKey, trailName2, null);
        DenyDescribeTrails(ak, sk, trailName2, null);
        DenyGetTrailStatus(ak, sk, trailName2, null);
        DenyPutEventSelectors(ak, sk, trailName2, null);
        DenyGetEventSelectors(ak, sk, trailName2, null);
        DenyStartLogging(ak, sk, trailName2, null);
        DenyStopLogging(ak, sk, trailName2, null);
        DenyUpdateTrail(ak, sk, trailName2, null);
        DenyLookupEvents(ak, sk, trailName2, null);
        DenyDeleteTrail(ak, sk, trailName2, null);
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
    
    private void AllowCreateTrail(String ak,String sk,String trailName,Map<String, String> headers) {
        Pair<Integer, String> createTrail=CloudTrailInterfaceTestUtils.CreateTrail(ak, sk, trailName, bucketName,headers);
        assertEquals(200, createTrail.first().intValue());
    }
    
    private void DenyCreateTrail(String ak,String sk,String trailName,Map<String, String> headers) {
        AkSkMeta aksk = new AkSkMeta();
        aksk.accessKey = ak;
        try {
            boolean exist = metaClient.akskSelectWithoutCache(aksk);
            assertTrue(exist);
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        String userName=aksk.userName;
        Pair<Integer, String> createTrail=CloudTrailInterfaceTestUtils.CreateTrail(ak, sk, trailName, bucketName,headers);
        assertEquals(403, createTrail.first().intValue());
        AssertAccessDenyString(createTrail.second(), "CreateTrail", userName, "trail/"+trailName);
    }
    
    private void AllowDescribeTrails(String ak,String sk,String trailName,Map<String, String> headers) {
        Pair<Integer, String> describeTrails=CloudTrailInterfaceTestUtils.DescribeTrails(ak, sk, Arrays.asList(trailName),headers);
        assertEquals(200, describeTrails.first().intValue());
    }
    
    private void DenyDescribeTrails(String ak,String sk,String trailName,Map<String, String> headers) {
        AkSkMeta aksk = new AkSkMeta();
        aksk.accessKey = ak;
        try {
            boolean exist = metaClient.akskSelectWithoutCache(aksk);
            assertTrue(exist);
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        String userName=aksk.userName;
        Pair<Integer, String> describeTrails=CloudTrailInterfaceTestUtils.DescribeTrails(ak, sk, Arrays.asList(trailName),headers);
        assertEquals(403, describeTrails.first().intValue());
        AssertAccessDenyString(describeTrails.second(), "DescribeTrails", userName, "trail/*");
    }
    
    private void AllowGetTrailStatus(String ak,String sk,String trailName,Map<String, String> headers) {
        Pair<Integer, String> getTrailStatus=CloudTrailInterfaceTestUtils.GetTrailStatus(ak, sk, trailName,headers);
        assertEquals(200, getTrailStatus.first().intValue());

    }
    
    private void DenyGetTrailStatus(String ak,String sk,String trailName,Map<String, String> headers) {
        AkSkMeta aksk = new AkSkMeta();
        aksk.accessKey = ak;
        try {
            boolean exist = metaClient.akskSelectWithoutCache(aksk);
            assertTrue(exist);
        } catch (IOException e) {
            e.printStackTrace();
        }  
        String userName=aksk.userName;
        
        Pair<Integer, String> getTrailStatus=CloudTrailInterfaceTestUtils.GetTrailStatus(ak, sk, trailName,headers);
        assertEquals(403, getTrailStatus.first().intValue());
        AssertAccessDenyString(getTrailStatus.second(), "GetTrailStatus", userName, "trail/"+trailName);
        
    }
    
    private void AllowPutEventSelectors(String ak,String sk,String trailName,Map<String, String> headers) {
        Pair<Integer, String> putEventSelectors=CloudTrailInterfaceTestUtils.PutEventSelectors(ak, sk, trailName,"All",headers);
        assertEquals(200, putEventSelectors.first().intValue());
    }
    
    private void DenyPutEventSelectors(String ak,String sk,String trailName,Map<String, String> headers) {
        AkSkMeta aksk = new AkSkMeta();
        aksk.accessKey = ak;
        try {
            boolean exist = metaClient.akskSelectWithoutCache(aksk);
            assertTrue(exist);
        } catch (IOException e) {
            e.printStackTrace();
        }  
        String userName=aksk.userName;
        
        Pair<Integer, String> putEventSelectors=CloudTrailInterfaceTestUtils.PutEventSelectors(ak, sk, trailName,"All",headers);
        assertEquals(403, putEventSelectors.first().intValue());
        AssertAccessDenyString(putEventSelectors.second(), "PutEventSelectors", userName, "trail/"+trailName);
    }
    
    private void AllowGetEventSelectors(String ak,String sk,String trailName,Map<String, String> headers) {
        Pair<Integer, String> getEventSelectors=CloudTrailInterfaceTestUtils.GetEventSelectors(ak, sk, trailName,headers);
        assertEquals(200, getEventSelectors.first().intValue());
    }
    
    private void DenyGetEventSelectors(String ak,String sk,String trailName,Map<String, String> headers) {
        AkSkMeta aksk = new AkSkMeta();
        aksk.accessKey = ak;
        try {
            boolean exist = metaClient.akskSelectWithoutCache(aksk);
            assertTrue(exist);
        } catch (IOException e) {
            e.printStackTrace();
        }  
        String userName=aksk.userName;
        
        Pair<Integer, String> getEventSelectors=CloudTrailInterfaceTestUtils.GetEventSelectors(ak, sk, trailName,headers);
        assertEquals(403, getEventSelectors.first().intValue());
        AssertAccessDenyString(getEventSelectors.second(), "GetEventSelectors", userName, "trail/"+trailName);
    }
    
    private void AllowUpdateTrail(String ak,String sk,String trailName,Map<String, String> headers) {
        Pair<Integer, String> updateTrail=CloudTrailInterfaceTestUtils.UpdateTrail(ak, sk, trailName,null,null,headers); 
        assertEquals(200, updateTrail.first().intValue());
    }
    
    private void DenyUpdateTrail(String ak,String sk,String trailName,Map<String, String> headers) {
        AkSkMeta aksk = new AkSkMeta();
        aksk.accessKey = ak;
        try {
            boolean exist = metaClient.akskSelectWithoutCache(aksk);
            assertTrue(exist);
        } catch (IOException e) {
            e.printStackTrace();
        }  
        String userName=aksk.userName;
        
        Pair<Integer, String> updateTrail=CloudTrailInterfaceTestUtils.UpdateTrail(ak, sk, trailName,null,null,headers);
        assertEquals(403, updateTrail.first().intValue());
        AssertAccessDenyString(updateTrail.second(), "UpdateTrail", userName, "trail/"+trailName);
        
    }
    
    private void AllowStartLogging(String ak,String sk,String trailName,Map<String, String> headers) {
        Pair<Integer, String> startLogging=CloudTrailInterfaceTestUtils.StartLogging(ak, sk, trailName,headers);
        assertEquals(200, startLogging.first().intValue());

    }
    
    private void DenyStartLogging(String ak,String sk,String trailName,Map<String, String> headers) {
        AkSkMeta aksk = new AkSkMeta();
        aksk.accessKey = ak;
        try {
            boolean exist = metaClient.akskSelectWithoutCache(aksk);
            assertTrue(exist);
        } catch (IOException e) {
            e.printStackTrace();
        }  
        String userName=aksk.userName;
        
        Pair<Integer, String> startLogging=CloudTrailInterfaceTestUtils.StartLogging(ak, sk, trailName,headers);
        assertEquals(403, startLogging.first().intValue());
        AssertAccessDenyString(startLogging.second(), "StartLogging", userName, "trail/"+trailName); 
    }
    
    private void AllowStopLogging(String ak,String sk,String trailName,Map<String, String> headers) {
        Pair<Integer, String> stopLogging=CloudTrailInterfaceTestUtils.StopLogging(ak, sk, trailName,headers);
        assertEquals(200, stopLogging.first().intValue());
    }
    
    private void DenyStopLogging(String ak,String sk,String trailName,Map<String, String> headers) {
        AkSkMeta aksk = new AkSkMeta();
        aksk.accessKey = ak;
        try {
            boolean exist = metaClient.akskSelectWithoutCache(aksk);
            assertTrue(exist);
        } catch (IOException e) {
            e.printStackTrace();
        }  
        String userName=aksk.userName;
        
        Pair<Integer, String> stopLogging=CloudTrailInterfaceTestUtils.StopLogging(ak, sk, trailName,headers);  
        assertEquals(403, stopLogging.first().intValue());
        AssertAccessDenyString(stopLogging.second(), "StopLogging", userName, "trail/"+trailName);   
    }
    
    private void AllowLookupEvents(String ak,String sk,String trailName,Map<String, String> headers) {
        Pair<Integer, String> lookupEvents=CloudTrailInterfaceTestUtils.LookupEvents(ak, sk, "EventSource","oos-cn-cloudtrail.ctyunapi.cn",headers);
        assertEquals(200, lookupEvents.first().intValue());
    }
    
    private void DenyLookupEvents(String ak,String sk,String trailName,Map<String, String> headers) {
        AkSkMeta aksk = new AkSkMeta();
        aksk.accessKey = ak;
        try {
            boolean exist = metaClient.akskSelectWithoutCache(aksk);
            assertTrue(exist);
        } catch (IOException e) {
            e.printStackTrace();
        }  
        String userName=aksk.userName;
        
        Pair<Integer, String> lookupEvents=CloudTrailInterfaceTestUtils.LookupEvents(ak, sk, "EventSource","oos-cn-cloudtrail.ctyunapi.cn",headers);
        assertEquals(403, lookupEvents.first().intValue());
        AssertAccessDenyString(lookupEvents.second(), "LookupEvents", userName, "trail/*");  
    }
    
    private void AllowDeleteTrail(String ak,String sk,String trailName,Map<String, String> headers) {
        Pair<Integer, String> deleteTrail=CloudTrailInterfaceTestUtils.DeleteTrail(ak, sk, trailName,headers);
        assertEquals(200, deleteTrail.first().intValue());
    }
    
    private void DenyDeleteTrail(String ak,String sk,String trailName,Map<String, String> headers) {
        AkSkMeta aksk = new AkSkMeta();
        aksk.accessKey = ak;
        try {
            boolean exist = metaClient.akskSelectWithoutCache(aksk);
            assertTrue(exist);
        } catch (IOException e) {
            e.printStackTrace();
        }  
        String userName=aksk.userName;
        
        Pair<Integer, String> deleteTrail=CloudTrailInterfaceTestUtils.DeleteTrail(ak, sk, trailName,headers);
        assertEquals(403, deleteTrail.first().intValue());
        AssertAccessDenyString(deleteTrail.second(), "DeleteTrail", userName, "trail/"+trailName);
        
    }  
    
    private void AssertAccessDenyString(String xml,String methodString,String userName,String resource) {
        try {
            JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
            assertEquals("AccessDenied", error.get("Code"));
            assertEquals("User: arn:ctyun:iam::"+accountId+":user/"+userName+" is not authorized to perform: cloudtrail:"+methodString+" on resource: arn:ctyun:cloudtrail::"+accountId+":"+resource+".", error.get("Message"));
            String errorResource = resource.split("/")[1];
            errorResource = "*".equals(errorResource) ? "/" : errorResource;
            assertEquals(errorResource, error.get("Resource"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }
    
    private static String OneDay0UTCTimeString(int offset) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        Calendar calendar=Calendar.getInstance();
        calendar.add(Calendar.DATE ,offset);
        calendar.set(Calendar.HOUR_OF_DAY, 0);
        calendar.set(Calendar.MINUTE, 0);
        calendar.set(Calendar.SECOND, 0);
        Date date=calendar.getTime();
        String dayString=dateFormat.format(date);
        System.out.println(dayString);
        return dayString;
    }

}
