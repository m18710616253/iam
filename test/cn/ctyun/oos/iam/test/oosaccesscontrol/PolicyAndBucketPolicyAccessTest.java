package cn.ctyun.oos.iam.test.oosaccesscontrol;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.plaf.nimbus.NimbusLookAndFeel;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.common.Consts;
import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.hbase.HBaseUserToTag;
import cn.ctyun.oos.hbase.HBaseVSNTag;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Principal;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.HttpsRequestUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.metadata.UserToTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta.VSNTagType;
import common.tuple.Pair;

public class PolicyAndBucketPolicyAccessTest {
    
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    public static final String regionName="cd";
    
    public static final int jettyHttpPort=80;
    public static final int jettyHttpsPort=8444;
    
    public static final String httpOrHttps="http";
    public static final int jettyport=jettyHttpPort;
    
//    public static final String httpOrHttps="https";
//    public static final int jettyport=jettyHttpsPort;
    
    public static final String signVersion="V4";
    
    
    public static final String bucketName1="yx-bucket-1";
    
    
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
    
    
    
    
    
    public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();
    static Configuration globalConf = GlobalHHZConfig.getConfig();

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
//        IAMTestUtils.TrancateTable("oos-aksk-yx");
//        IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);
//        
//        // 创建根用户
//        owner.email=ownerName;
//        owner.setPwd("123456");
//        owner.maxAKNum=10;
//        owner.displayName="测试根用户";
//        owner.bucketCeilingNum=10;
//        metaClient.ownerInsertForTest(owner);
//        
//        AkSkMeta aksk=new AkSkMeta(owner.getId());
//        aksk.accessKey=accessKey;
//        aksk.setSecretKey(secretKey);
//        aksk.isPrimary=1;
//        metaClient.akskInsert(aksk);
//        
//        
//        String UserName1=user1Name;
//        User user1=new User();
//        user1.accountId=accountId;
//        user1.userName=UserName1;
//        user1.userId="test1abc";
//        user1.createDate=System.currentTimeMillis();
//        try {
//            boolean success=HBaseUtils.checkAndCreate(user1);
//            assertTrue(success);
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//
//        // 插入数据库aksk
//        AkSkMeta aksk1 = new AkSkMeta(owner.getId());
//        aksk1.isRoot = 0;
//        aksk1.userId = user1.userId;
//        aksk1.userName = UserName1;
//        aksk1.accessKey=user1accessKey1;
//        aksk1.setSecretKey(user1secretKey1);
//        metaClient.akskInsert(aksk1);
//        user1.accessKeys = new ArrayList<>();
//        user1.accessKeys.add(aksk1.accessKey);
//        
//        aksk1.accessKey=user1accessKey2;
//        aksk1.setSecretKey(user1secretKey2);
//        metaClient.akskInsert(aksk1);
//        user1.accessKeys.add(aksk1.accessKey);
//        HBaseUtils.put(user1);
//        
//        String UserName2=user2Name;
//        User user2=new User();
//        user2.accountId=accountId;
//        user2.userName=UserName2;
//        user2.userId="Test1Abc";
//        user2.createDate=System.currentTimeMillis();
//        try {
//            boolean success=HBaseUtils.checkAndCreate(user2);
//            assertTrue(success);
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//        
//        AkSkMeta aksk2 = new AkSkMeta(owner.getId());
//        aksk2.isRoot = 0;
//        aksk2.userId = user2.userId;
//        aksk2.userName = UserName2;
//        aksk2.accessKey=user2accessKey;
//        aksk2.setSecretKey(user2secretKey);
//        metaClient.akskInsert(aksk2);
//        user2.accessKeys = new ArrayList<>();
//        user2.userName=UserName2;
//        user2.accessKeys.add(aksk2.accessKey);
//        HBaseUtils.put(user2);
//        
//        String UserName3=user3Name;
//        User user3=new User();
//        user3.accountId=accountId;
//        user3.userName=UserName3;
//        user3.userId="abc1";
//        user3.createDate=System.currentTimeMillis();
//        try {
//            boolean success=HBaseUtils.checkAndCreate(user3);
//            assertTrue(success);
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//        
//        AkSkMeta aksk3 = new AkSkMeta(owner.getId());
//        aksk3.isRoot = 0;
//        aksk3.userId = user3.userId;
//        aksk3.userName = UserName3;
//        aksk3.accessKey=user3accessKey;
//        aksk3.setSecretKey(user3secretKey);
//        metaClient.akskInsert(aksk3);
//        
//        user3.accessKeys = new ArrayList<>();
//        user3.userName=UserName3;
//        user3.accessKeys.add(aksk3.accessKey);
//        HBaseUtils.put(user3);   
//        
//        HBaseAdmin globalHbaseAdmin = new HBaseAdmin(globalConf);
//        
//        HBaseUserToTag.dropTable(GlobalHHZConfig.getConfig());
//        HBaseUserToTag.createTable(globalHbaseAdmin);
//        HBaseVSNTag.dropTable(GlobalHHZConfig.getConfig());
//        HBaseVSNTag.createTable(globalHbaseAdmin);
//        Thread.sleep(1000);
//        
//        VSNTagMeta dataTag1;
//        VSNTagMeta metaTag1;
//        
//        
//        dataTag1 = new VSNTagMeta("tag1", Arrays.asList(new String[] { "yxregion1","yxregion2"}), VSNTagType.DATA);
//        metaClient.vsnTagInsert(dataTag1);
//        metaTag1 = new VSNTagMeta("mtag1", Arrays.asList(new String[] { "yxregion1" }), VSNTagType.META);
//        metaClient.vsnTagInsert(metaTag1);
//        
//        UserToTagMeta user2Tag1 = new UserToTagMeta(owner.getId(),
//                Arrays.asList(new String[] { dataTag1.getTagName() }), VSNTagType.DATA);
//        metaClient.userToTagInsert(user2Tag1);
//        UserToTagMeta user2Tag2 = new UserToTagMeta(owner.getId(),
//                Arrays.asList(new String[] { metaTag1.getTagName() }), VSNTagType.META);
//        metaClient.userToTagInsert(user2Tag2);
        
    }

    @Before
    public void setUp() throws Exception {
        // 清空iam-policy表
        // iam-user表中去掉policy关联
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        IAMTestUtils.TrancateTable("oos-bucket-yx");
        IAMTestUtils.UpdateUserTable("policy","policyCount");
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName1, null, null, null, null, params);
    }

    @Test
    public void test_Action_ListBucket_PolicyNo_BucketPolicyAllow_HeadBucket()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:ListBucket"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        int head1=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(200, head1);
    }
    
    @Test
    public void test_Action_ListBucket_PolicyNo_BucketPolicyDeny_HeadBucket() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:ListBucket"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        int head1=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(403, head1);
    }
    
    @Test
    public void test_Action_ListBucket_PolicyAllow_BucketPolicyAllow_HeadBucket() {
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        // bucket policy 允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:ListBucket"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        int head1=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(200, head1);
        
    }
    
    @Test
    public void test_Action_ListBucket_PolicyAllow_BucketPolicyDeny_HeadBucket() {
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:ListBucket"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        int head1=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(403, head1);
    }
    
    @Test
    public void test_Action_ListBucket_PolicyDeny_BucketPolicyAllow_HeadBucket() {
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:ListBucket"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        int head1=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(403, head1);
    }
    
    @Test
    public void test_Action_ListBucket_PolicyDeny_BucketPolicyDeny_HeadBucket() {
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:ListBucket"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        int head1=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(403, head1);
    }
    
    @Test
    public void test_Action_ListBucket_PolicyNo_BucketPolicyAllow_GetBucket()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:ListBucket"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(200, getresult1.first().intValue());
        assertTrue(getresult1.second().contains("ListBucketResult"));
        
    }
    
    @Test
    public void test_Action_ListBucket_PolicyNo_BucketPolicyDeny_GetBucket() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:ListBucket"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(getresult1.second());
    }
    
    @Test
    public void test_Action_ListBucket_PolicyAllow_BucketPolicyAllow_GetBucket() {
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        // bucket policy 允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:ListBucket"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(200, getresult1.first().intValue());
        assertTrue(getresult1.second().contains("ListBucketResult"));
        
    }
    
    @Test
    public void test_Action_ListBucket_PolicyAllow_BucketPolicyDeny_GetBucket() {
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:ListBucket"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(getresult1.second());
        
    }
    
    @Test
    public void test_Action_ListBucket_PolicyDeny_BucketPolicyAllow_GetBucket() {
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:ListBucket"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringIAM(getresult1.second(), "ListBucket", user1Name, bucketName);
    }
    
    @Test
    public void test_Action_ListBucket_PolicyDeny_BucketPolicyDeny_GetBucket() {
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:ListBucket"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(getresult1.second());
    }
    
    @Test
    public void test_Action_ListBucketMultipartUploads_PolicyNo_BucketPolicyAllow()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(200, getresult1.first().intValue());
        assertTrue(getresult1.second().contains("ListMultipartUploadsResult"));
        
    }
    
    @Test
    public void test_Action_ListBucketMultipartUploads_PolicyNo_BucketPolicyDeny() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(getresult1.second());
    }
    
    @Test
    public void test_Action_ListBucketMultipartUploads_PolicyAllow_BucketPolicyAllow() {
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(200, getresult1.first().intValue());
        assertTrue(getresult1.second().contains("ListMultipartUploadsResult"));
        
    }
    
    @Test
    public void test_Action_ListBucketMultipartUploads_PolicyAllow_BucketPolicyDeny() {
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(getresult1.second());
        
    }
    
    @Test
    public void test_Action_ListBucketMultipartUploads_PolicyDeny_BucketPolicyAllow() {
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringIAM(getresult1.second(), "ListBucketMultipartUploads", user1Name, bucketName);
    }
    
    @Test
    public void test_Action_ListBucketMultipartUploads_PolicyDeny_BucketPolicyDeny() {
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(getresult1.second());
    }
    
    @Test
    public void test_Action_PutObject_PolicyNo_BucketPolicyAllow_putObject()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, "put1.txt","putContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
    }
    
    @Test
    public void test_Action_PutObject_PolicyNo_BucketPolicyDeny_putObject() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, "put1.txt","putContent1",null);
        assertEquals(403, putresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(putresult1.second());
    }
    
    @Test
    public void test_Action_PutObject_PolicyAllow_BucketPolicyAllow_putObject() {
        String bucketName=bucketName1;
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, "put1.txt","putContent1",null);
        assertEquals(200, putresult1.first().intValue());
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyAllow_BucketPolicyDeny_putObject() {
        String bucketName=bucketName1;
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, "put1.txt","putContent1",null);
        assertEquals(403, putresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(putresult1.second());
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyAllow_putObject() {
        String bucketName=bucketName1;
        String objectName="put1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"putContent1",null);
        assertEquals(403, putresult1.first().intValue());
        AssertAccessDeniedStringIAM(putresult1.second(), "PutObject", user1Name, bucketName+"/"+objectName);
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyDeny_putObject() {
        String bucketName=bucketName1;
        String objectName="put1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"putContent1",null);
        assertEquals(403, putresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(putresult1.second());
    }
    
    @Test
    public void test_Action_PutObject_PolicyNo_BucketPolicyAllow_postObject()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        String objectName="post1.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"postContent1",null);
        assertEquals(204, putresult1.first().intValue()); 
    }
    
    @Test
    public void test_Action_PutObject_PolicyNo_BucketPolicyDeny_postObject() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        String objectName="post1.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"postContent1",null);
        assertEquals(403, putresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(putresult1.second());
    }
    
    @Test
    public void test_Action_PutObject_PolicyAllow_BucketPolicyAllow_postObject() {
        String bucketName=bucketName1;
        String objectName="post1.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"postContent1",null);
        assertEquals(204, putresult1.first().intValue());
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyAllow_BucketPolicyDeny_postObject() {
        String bucketName=bucketName1;
        String objectName="post1.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"putContent1",null);
        assertEquals(403, putresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(putresult1.second());
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyAllow_postObject() {
        String bucketName=bucketName1;
        String objectName="post1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"putContent1",null);
        assertEquals(403, putresult1.first().intValue());
        AssertAccessDeniedStringIAM(putresult1.second(), "PutObject", user1Name, bucketName+"/"+objectName);
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyDeny_postObject() {
        String bucketName=bucketName1;
        String objectName="put1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"putContent1",null);
        assertEquals(403, putresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(putresult1.second());
    }
    
    @Test
    /*
     * copy需要源的GetObject权限，目标的PutObject权限
     */
    public void test_Action_PutGetObject_PolicyNo_BucketPolicyAllow_CopyObject()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        String srcObjectName="srcObject";
        String desObjectName="desObject";
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject","s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, srcObjectName, "srcContent", null);
        Pair<Integer, String> copyresult1=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, srcObjectName,desObjectName,null);
        assertEquals(200, copyresult1.first().intValue()); 
    }
    
    @Test 
    public void test_Action_PutGetObject_PolicyNo_BucketPolicyDeny_CopyObject() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        String srcObjectName="srcObject";
        String desObjectName="desObject";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject","s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> copyresult1=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, srcObjectName,desObjectName,null);
        assertEquals(403, copyresult1.first().intValue()); 
        AssertAccessDeniedStringBucketPolicy(copyresult1.second());
    }
    
    @Test
    public void test_Action_PutGetObject_PolicyAllow_BucketPolicyAllow_CopyObject() {
        String bucketName=bucketName1;
        String srcObjectName="srcObject";
        String desObjectName="desObject";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject","oos:GetObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject","s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> copyresult1=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, srcObjectName,desObjectName,null);
        assertEquals(200, copyresult1.first().intValue());
        
    }
    
    @Test
    public void test_Action_PutGetObject_PolicyAllow_BucketPolicyDeny_CopyObject() {
        String bucketName=bucketName1;
        String srcObjectName="srcObject";
        String desObjectName="desObject";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject","oos:GetObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject","s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> copyresult1=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, srcObjectName,desObjectName,null);
        assertEquals(403, copyresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(copyresult1.second());
        
    }
    
    @Test
    public void test_Action_PutGetObject_PolicyDeny_BucketPolicyAllow_CopyObject() {
        String bucketName=bucketName1;
        String srcObjectName="srcObject";
        String desObjectName="desObject";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject","oos:GetObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject","s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> copyresult1=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, srcObjectName,desObjectName,null);
        assertEquals(403, copyresult1.first().intValue());
        AssertAccessDeniedStringIAM(copyresult1.second(), "PutObject", user1Name, bucketName+"/"+desObjectName);
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyDeny_CopyObject() {
        String bucketName=bucketName1;
        String srcObjectName="srcObject";
        String desObjectName="desObject";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject","oos:GetObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject","s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> copyresult1=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, srcObjectName,desObjectName,null);
        assertEquals(403, copyresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(copyresult1.second());
    }
    
    @Test
    public void test_Action_PutObject_PolicyNo_BucketPolicyAllow_initiateMultipartUpload()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,null);
        assertEquals(200, putresult1.first().intValue()); 
        assertTrue(putresult1.second().contains("InitiateMultipartUploadResult"));
    }
    
    @Test
    public void test_Action_PutObject_PolicyNo_BucketPolicyDeny_initiateMultipartUpload() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,null);
        assertEquals(403, putresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(putresult1.second());
    }
    
    @Test
    public void test_Action_PutObject_PolicyAllow_BucketPolicyAllow_initiateMultipartUpload() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,null);
        assertEquals(200, putresult1.first().intValue());
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyAllow_BucketPolicyDeny_initiateMultipartUpload() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,null);
        assertEquals(403, putresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(putresult1.second());
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyAllow_initiateMultipartUpload() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,null);
        assertEquals(403, putresult1.first().intValue());
        AssertAccessDeniedStringIAM(putresult1.second(), "PutObject", user1Name, bucketName+"/"+objectName);
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyDeny_initiateMultipartUpload() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,null);
        assertEquals(403, putresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(putresult1.second());
    }
    
    @Test
    public void test_Action_PutObject_PolicyNo_BucketPolicyAllow_Uploadpart()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyNo_BucketPolicyDeny_Uploadpart() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(403, uploadPartResult1.first().intValue()); 
        AssertAccessDeniedStringBucketPolicy(uploadPartResult1.second());
    }
    
    @Test
    public void test_Action_PutObject_PolicyAllow_BucketPolicyAllow_Uploadpart() {
        String bucketName=bucketName1;
        String objectName="multi2.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyAllow_BucketPolicyDeny_Uploadpart() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(403, uploadPartResult1.first().intValue()); 
        AssertAccessDeniedStringBucketPolicy(uploadPartResult1.second());
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyAllow_Uploadpart() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(403, uploadPartResult1.first().intValue()); 
        AssertAccessDeniedStringIAM(uploadPartResult1.second(), "PutObject", user1Name, bucketName+"/"+objectName);
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyDeny_Uploadpart() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(403, uploadPartResult1.first().intValue()); 
        AssertAccessDeniedStringBucketPolicy(uploadPartResult1.second());
    }
    
    @Test
    /*
     * bucketPolicy 不包括copy part
     */
    public void test_Action_PutObject_PolicyNo_BucketPolicyAllow_Copypart()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, "src.txt", "srcContent",null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_CopyPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,uploadId,1,"src.txt",null);
        assertEquals(403, uploadPartResult1.first().intValue()); 
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyNo_BucketPolicyDeny_Copypart() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, "src.txt", "srcContent",null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_CopyPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,uploadId,1,"src.txt",null);
        assertEquals(403, uploadPartResult1.first().intValue()); 
        AssertAccessDeniedStringIAM(uploadPartResult1.second(), "PutObject", user1Name, bucketName+"/"+objectName);
    }
    
    @Test
    public void test_Action_PutObject_PolicyAllow_BucketPolicyAllow_Copypart() {
        String bucketName=bucketName1;
        String objectName="multi3.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, "src.txt", "srcContent",null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_CopyPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,uploadId,1,"src.txt",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        
        System.out.println(getCopyPartEtag(uploadPartResult1.second()));
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyAllow_BucketPolicyDeny_Copypart() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, "src.txt", "srcContent",null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_CopyPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,uploadId,1,"src.txt",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyAllow_Copypart() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, "src.txt", "srcContent",null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_CopyPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,uploadId,1,"src.txt",null);
        assertEquals(403, uploadPartResult1.first().intValue()); 
        AssertAccessDeniedStringIAM(uploadPartResult1.second(), "PutObject", user1Name, bucketName+"/"+objectName);
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyDeny_Copypart() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, "src.txt", "srcContent",null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_CopyPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,uploadId,1,"src.txt",null);
        assertEquals(403, uploadPartResult1.first().intValue()); 
        AssertAccessDeniedStringIAM(uploadPartResult1.second(), "PutObject", user1Name, bucketName+"/"+objectName);
    }
    
    @Test
    public void test_Action_PutObject_PolicyNo_BucketPolicyAllow_completeMultipartUpload()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId, partEtagMap,null);
        assertEquals(200, completeResult.first().intValue()); 
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyNo_BucketPolicyDeny_completeMultipartUpload() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId, partEtagMap,null);
        assertEquals(403, completeResult.first().intValue()); 
        AssertAccessDeniedStringBucketPolicy(completeResult.second());
    }
    
    @Test
    public void test_Action_PutObject_PolicyAllow_BucketPolicyAllow_completeMultipartUpload() {
        String bucketName=bucketName1;
        String objectName="multi2.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId, partEtagMap,null);
        assertEquals(200, completeResult.first().intValue());         
    }
    
    @Test
    public void test_Action_PutObject_PolicyAllow_BucketPolicyDeny_completeMultipartUpload() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId, partEtagMap,null);
        assertEquals(403, completeResult.first().intValue()); 
        AssertAccessDeniedStringBucketPolicy(completeResult.second());
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyAllow_completeMultipartUpload() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId, partEtagMap,null);
        assertEquals(403, completeResult.first().intValue()); 
        AssertAccessDeniedStringIAM(completeResult.second(), "PutObject", user1Name, bucketName+"/"+objectName);
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyDeny_completeMultipartUpload() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId, partEtagMap,null);
        assertEquals(403, completeResult.first().intValue()); 
        AssertAccessDeniedStringBucketPolicy(completeResult.second());
    }
    
    @Test
    public void test_Action_PutObject_PolicyNo_BucketPolicyAllow_abortMultipartUpload()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:AbortMultipartUpload"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId, null);
        assertEquals(204, aborteResult.first().intValue()); 
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyNo_BucketPolicyDeny_abortMultipartUpload() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:AbortMultipartUpload"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId, null);
        assertEquals(403, aborteResult.first().intValue()); 
        AssertAccessDeniedStringBucketPolicy(aborteResult.second());
    }
    
    @Test
    public void test_Action_PutObject_PolicyAllow_BucketPolicyAllow_abortMultipartUpload() {
        String bucketName=bucketName1;
        String objectName="multi2.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:AbortMultipartUpload"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:AbortMultipartUpload"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId, null);
        assertEquals(204, aborteResult.first().intValue());  
    }
    
    @Test
    public void test_Action_PutObject_PolicyAllow_BucketPolicyDeny_abortMultipartUpload() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:AbortMultipartUpload"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:AbortMultipartUpload"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId, null);
        assertEquals(403, aborteResult.first().intValue());
        AssertAccessDeniedStringBucketPolicy(aborteResult.second());
        
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyAllow_abortMultipartUpload() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:AbortMultipartUpload"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:AbortMultipartUpload"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId, null);
        assertEquals(403, aborteResult.first().intValue());
        AssertAccessDeniedStringIAM(aborteResult.second(), "AbortMultipartUpload", user1Name, bucketName+"/"+objectName);
    }
    
    @Test
    public void test_Action_PutObject_PolicyDeny_BucketPolicyDeny_abortMultipartUpload() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:AbortMultipartUpload"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:AbortMultipartUpload"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId, null);
        assertEquals(403, aborteResult.first().intValue());
        AssertAccessDeniedStringBucketPolicy(aborteResult.second());
    }
    
    @Test
    public void test_Action_ListMultipartUploadParts_PolicyNo_BucketPolicyAllow_ListPart()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:ListMultipartUploadParts"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId,null);
        assertEquals(200, ListPartResult.first().intValue()); 
        assertTrue(ListPartResult.second().contains("ListPartsResult"));
        
    }
    
    @Test
    public void test_Action_ListMultipartUploadParts_PolicyNo_BucketPolicyDeny_ListPart() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:ListMultipartUploadParts"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId,null);
        assertEquals(403, ListPartResult.first().intValue()); 
        AssertAccessDeniedStringBucketPolicy(ListPartResult.second());
    }
    
    @Test
    public void test_Action_ListMultipartUploadParts_PolicyAllow_BucketPolicyAllow_ListPart() {
        String bucketName=bucketName1;
        String objectName="multi2.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListMultipartUploadParts"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:ListMultipartUploadParts"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId,null);
        assertEquals(200, ListPartResult.first().intValue());   
        assertTrue(ListPartResult.second().contains("ListPartsResult"));
    }
    
    @Test
    public void test_Action_ListMultipartUploadParts_PolicyAllow_BucketPolicyDeny_ListPart() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListMultipartUploadParts"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:ListMultipartUploadParts"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId,null);
        assertEquals(403, ListPartResult.first().intValue()); 
        AssertAccessDeniedStringBucketPolicy(ListPartResult.second());
        
    }
    
    @Test
    public void test_Action_ListMultipartUploadParts_PolicyDeny_BucketPolicyAllow_ListPart() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListMultipartUploadParts"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:ListMultipartUploadParts"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId,null);
        assertEquals(403, ListPartResult.first().intValue()); 
        AssertAccessDeniedStringIAM(ListPartResult.second(), "ListMultipartUploadParts", user1Name, bucketName+"/"+objectName);
    }
    
    @Test
    public void test_Action_ListMultipartUploadParts_PolicyDeny_BucketPolicyDeny_ListPart() {
        String bucketName=bucketName1;
        String objectName="multi1.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListMultipartUploadParts"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:ListMultipartUploadParts"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", uploadPartResult2.second());
        
        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName, uploadId,null);
        assertEquals(403, ListPartResult.first().intValue()); 
        AssertAccessDeniedStringBucketPolicy(ListPartResult.second());
    }
    
    @Test
    public void test_Action_GetObject_PolicyNo_BucketPolicyAllow_HeadObject()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        String objectName="get.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"getContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        int getresult1=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(200, getresult1);
    }
    
    @Test
    public void test_Action_GetObject_PolicyNo_BucketPolicyDeny_HeadObject() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        String objectName="get.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"getContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        int getresult1=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, getresult1);
    }
    
    @Test
    public void test_Action_GetObject_PolicyAllow_BucketPolicyAllow_HeadObject() {
        String bucketName=bucketName1;
        String objectName="get.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:GetObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"getContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        int getresult1=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(200, getresult1);
        
    }
    
    @Test
    public void test_Action_GetObject_PolicyAllow_BucketPolicyDeny_HeadObject() {
        String bucketName=bucketName1;
        String objectName="get.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:GetObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"getContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        int getresult1=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, getresult1);
        
    }
    
    @Test
    public void test_Action_GetObject_PolicyDeny_BucketPolicyAllow_HeadObject() {
        String bucketName=bucketName1;
        String objectName="get.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:GetObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"getContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        int getresult1=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, getresult1);
    }
    
    @Test
    public void test_Action_GetObject_PolicyDeny_BucketPolicyDeny_HeadObject() {
        String bucketName=bucketName1;
        String objectName="get.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:GetObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"getContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        int getresult1=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, getresult1);
    }
    
    @Test
    public void test_Action_GetObject_PolicyNo_BucketPolicyAllow_GetObject()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        String objectName="get.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"getContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(200, getresult1.first().intValue());
    }
    
    @Test
    public void test_Action_GetObject_PolicyNo_BucketPolicyDeny_GetObject() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        String objectName="get.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"getContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        Pair<Integer, String>getresult1=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(getresult1.second());
    }
    
    @Test
    public void test_Action_GetObject_PolicyAllow_BucketPolicyAllow_GetObject() {
        String bucketName=bucketName1;
        String objectName="get.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:GetObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"getContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(200, getresult1.first().intValue());
        
    }
    
    @Test
    public void test_Action_GetObject_PolicyAllow_BucketPolicyDeny_GetObject() {
        String bucketName=bucketName1;
        String objectName="get.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:GetObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"getContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(getresult1.second());
        
    }
    
    @Test
    public void test_Action_GetObject_PolicyDeny_BucketPolicyAllow_GetObject() {
        String bucketName=bucketName1;
        String objectName="get.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:GetObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"getContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringIAM(getresult1.second(), "GetObject", user1Name, bucketName+"/"+objectName);
    }
    
    @Test
    public void test_Action_GetObject_PolicyDeny_BucketPolicyDeny_GetObject() {
        String bucketName=bucketName1;
        String objectName="get.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:GetObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:GetObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"getContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(getresult1.second());
    }
    
    @Test
    public void test_Action_DeleteObject_PolicyNo_BucketPolicyAllow_DeleteObject()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        String objectName="delete.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:DeleteObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"deleteContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(204, getresult1.first().intValue());
    }
    
    @Test
    public void test_Action_DeleteObject_PolicyNo_BucketPolicyDeny_DeleteObject() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1;
        String objectName="delete.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:DeleteObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"deleteContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        Pair<Integer, String>getresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(getresult1.second());
    }
    
    @Test
    public void test_Action_DeleteObject_PolicyAllow_BucketPolicyAllow_DeleteObject() {
        String bucketName=bucketName1;
        String objectName="delete.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:DeleteObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:DeleteObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"deleteContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(204, getresult1.first().intValue());
        
    }
    
    @Test
    public void test_Action_DeleteObject_PolicyAllow_BucketPolicyDeny_DeleteObject() {
        String bucketName=bucketName1;
        String objectName="delete.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:DeleteObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:DeleteObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"deleteContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(getresult1.second());
        
    }
    
    @Test
    public void test_Action_DeleteObject_PolicyDeny_BucketPolicyAllow_DeleteObject() {
        String bucketName=bucketName1;
        String objectName="delete.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:DeleteObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:DeleteObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"deleteContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringIAM(getresult1.second(), "DeleteObject", user1Name, bucketName+"/"+objectName);
    }
    
    @Test
    public void test_Action_DeleteObject_PolicyDeny_BucketPolicyDeny_DeleteObject() {
        String bucketName=bucketName1;
        String objectName="delete.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:DeleteObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:DeleteObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"deleteContent1",null);
        assertEquals(200, putresult1.first().intValue()); 
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, getresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(getresult1.second());
    }
    
    @Test
    /*
     * bucket policy 不支持Bucket_Delete_MultipleObjects
     */
    public void test_Action_DeleteMultipleObjects_PolicyNo_BucketPolicyAllow_DeleteMulit()  {
        // iam policy 不存在
        // bucket policy 允许
        String bucketName=bucketName1;
        String objectName="delete.txt";
        String objectName2="delete2.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:DeleteMultipleObjects"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"deleteContent1",null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName2,"deleteContent2",null);
         
        
        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_DeleteMulit(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,Arrays.asList(objectName,objectName2),null);
        assertEquals(403, delresult1.first().intValue());
        AssertAccessDeniedStringIAM(delresult1.second(), "DeleteMultipleObjects", user1Name, bucketName);
    }
    
    @Test
    public void test_Action_DeleteMultipleObjects_PolicyNo_BucketPolicyDeny_DeleteMulit() {
        // iam policy 不存在
        // bucket policy 不允许
        String bucketName=bucketName1; 
        String objectName="delete.txt";
        String objectName2="delete2.txt";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:DeleteMultipleObjects"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(policyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"deleteContent1",null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName2,"deleteContent2",null);
        
        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_DeleteMulit(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,Arrays.asList(objectName,objectName2),null);
        assertEquals(403, delresult1.first().intValue());
        AssertAccessDeniedStringIAM(delresult1.second(), "DeleteMultipleObjects", user1Name, bucketName);
    }
    
    @Test
    public void test_Action_DeleteMultipleObjects_PolicyAllow_BucketPolicyAllow_DeleteMulit() {
        String bucketName=bucketName1;
        String objectName="delete.txt";
        String objectName2="delete2.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:DeleteMultipleObjects"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:DeleteMultipleObjects"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"deleteContent1",null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName2,"deleteContent2",null);
        
        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_DeleteMulit(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,Arrays.asList(objectName,objectName2),null);
        assertEquals(200, delresult1.first().intValue());
        
    }
    
    @Test
    public void test_Action_DeleteMultipleObjects_PolicyAllow_BucketPolicyDeny_DeleteMulit() {
        String bucketName=bucketName1;
        String objectName="delete.txt";
        String objectName2="delete2.txt";
        // iam policy 允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:DeleteMultipleObjects"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:DeleteMultipleObjects"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"deleteContent1",null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName2,"deleteContent2",null);
        
        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_DeleteMulit(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,Arrays.asList(objectName,objectName2),null);
        assertEquals(200, delresult1.first().intValue());
        
    }
    
    @Test
    public void test_Action_DeleteMultipleObjects_PolicyDeny_BucketPolicyAllow_DeleteMulit() {
        String bucketName=bucketName1;
        String objectName="delete.txt";
        String objectName2="delete2.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:DeleteMultipleObjects"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:DeleteMultipleObjects"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"deleteContent1",null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName2,"deleteContent2",null);
        
        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_DeleteMulit(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,Arrays.asList(objectName,objectName2),null);
        assertEquals(403, delresult1.first().intValue());
        AssertAccessDeniedStringIAM(delresult1.second(), "DeleteMultipleObjects", user1Name, bucketName);
    }
    
    @Test
    public void test_Action_DeleteMultipleObjects_PolicyDeny_BucketPolicyDeny_DeleteMulit() {
        String bucketName=bucketName1;
        String objectName="delete.txt";
        String objectName2="delete2.txt";
        // iam policy 不允许
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:DeleteMultipleObjects"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 不允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:DeleteMultipleObjects"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName),null);
        System.out.println(bucketpolicyString);
        
        //
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, policyString, null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName,"deleteContent1",null);
        OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName,objectName2,"deleteContent2",null);
        
        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_DeleteMulit(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,Arrays.asList(objectName,objectName2),null);
        assertEquals(403, delresult1.first().intValue());
        AssertAccessDeniedStringIAM(delresult1.second(), "DeleteMultipleObjects", user1Name, bucketName);
    }
    
    @Test
    public void test_Condition_PolicyAllow_BucketPolicyAllow_Referer_StringEqualsAndStringNotEquals() {
        
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:Referer",Arrays.asList("http://www.mysite.com/login.html"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","aws:Referer",Arrays.asList("http://www.mysite.com/login.html"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("Referer", "http://www.mysite.com/login.html");
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", params);
        assertEquals(200, putresult1.first().intValue());
        
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("Referer", "http://www.testsite.com/register.html");
        Pair<Integer, String> putresult2 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "world", params2);
        assertEquals(200, putresult2.first().intValue());
    }
    
    @Test
    public void test_Condition_PolicyAllow_BucketPolicyAllow_Referer_StringLikeAndStringNotLike() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringLike","ctyun:Referer",Arrays.asList("http://www.mysite.com/*"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotLike","aws:Referer",Arrays.asList("http://www.mysite.com/*"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("Referer", "http://www.mysite.com/login.html");
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", params);
        assertEquals(200, putresult1.first().intValue());
        
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("Referer", "http://www.mysite.com/register.html");
        Pair<Integer, String> putresult2 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "world", params2);
        assertEquals(200, putresult2.first().intValue());
    }
    
    @Test
    public void test_Condition_PolicyAllow_BucketPolicyAllow_Referer_StringEqualsIgnoreCaseAndStringNotEqualsIgnoreCase() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:Referer",Arrays.asList("http://www.mysite.com/Login.html"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","aws:Referer",Arrays.asList("http://www.mysite.com/login.html"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("Referer", "http://www.mysite.com/Login.html");
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", params);
        assertEquals(200, putresult1.first().intValue());
        
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("Referer", "http://www.mysite.com/register.html");
        Pair<Integer, String> putresult2 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "world", params2);
        assertEquals(200, putresult2.first().intValue());
    }
    
    @Test
    public void test_Condition_PolicyAllow_BucketPolicyAllow_UserAgent_StringEqualsAndStringNotEquals() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:UserAgent",Arrays.asList("java/1.8.0_92"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","aws:UserAgent",Arrays.asList("java/1.8.0_92","java/1.8.0_91"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("User-Agent", "java/1.8.0_92");
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", params);
        assertEquals(200, putresult1.first().intValue());
        
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("User-Agent", "java/1.8.0_91");
        Pair<Integer, String> putresult2 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "world", params2);
        assertEquals(403, putresult2.first().intValue());
        AssertAccessDeniedStringIAM(putresult2.second(), "PutObject", user1Name, bucketName+"/"+objectName);
    }
    
    @Test
    public void test_Condition_PolicyAllow_BucketPolicyAllow_UserAgent_StringLikeAndStringNotLike() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:UserAgent",Arrays.asList("java/1.8.0_?2"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","aws:UserAgent",Arrays.asList("java/1.8.0_?2"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("User-Agent", "java/1.8.0_92");
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", params);
        assertEquals(200, putresult1.first().intValue());
        
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("User-Agent", "java/1.8.0_91");
        Pair<Integer, String> putresult2 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "world", params2);
        assertEquals(200, putresult2.first().intValue());
        
    }
    
    @Test
    public void test_Condition_PolicyAllow_BucketPolicyAllow_UserAgent_StringEqualsIgnoreCaseAndStringNotEqualsIgnoreCase() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:UserAgent",Arrays.asList("java/1.8.0_92"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","aws:UserAgent",Arrays.asList("java/1.8.0_92"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("User-Agent", "Java/1.8.0_92");
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", params);
        assertEquals(200, putresult1.first().intValue());
        
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("User-Agent", "Java/1.8.0_91");
        Pair<Integer, String> putresult2 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "world", params2);
        assertEquals(200, putresult2.first().intValue());
    }
    
    @Test
    public void test_Condition_PolicyAllow_BucketPolicyAllow_SourceIp() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("NotIpAddress","aws:SourceIp",Arrays.asList("192.168.1.1/24"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("X-Forwarded-For", "192.168.1.101");
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", params);
        assertEquals(200, putresult1.first().intValue());
        
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("Proxy-Client-IP", "192.168.1.101");
        Pair<Integer, String> putresult2 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "world", params2);
        assertEquals(200, putresult2.first().intValue());
    }
    
    @Test
    public void test_Condition_PolicyAllow_BucketPolicyAllow_SecureTransport() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("true"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("Bool","aws:SecureTransport",Arrays.asList("false"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);

        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put("https", "V2", jettyHttpsPort, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", null);
        assertEquals(200, putresult1.first().intValue());

        Pair<Integer, String> putresult2 = OOSInterfaceTestUtils.Object_Put("https", "V4", jettyHttpsPort, user1accessKey1, user1secretKey1, bucketName,objectName, "world", null);
        assertEquals(200, putresult2.first().intValue());
    }
    
    @Test
    public void test_Condition_PolicyAllow_BucketPolicyDeny_Referer() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringLike","ctyun:Referer",Arrays.asList("http://www.mysite.com/*"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringLike","aws:Referer",Arrays.asList("http://www.mysite.com/*"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("Referer", "http://www.mysite.com/login.html");
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", params);
        assertEquals(403, putresult1.first().intValue());

    }
    
    @Test
    public void test_Condition_PolicyDeny_BucketPolicyAllow_Referer() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringLike","ctyun:Referer",Arrays.asList("http://www.mysite.com/*"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringLike","aws:Referer",Arrays.asList("http://www.mysite.com/*"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("Referer", "http://www.mysite.com/login.html");
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", params);
        assertEquals(403, putresult1.first().intValue());
    }
    
    @Test
    public void test_Condition_PolicyAllow_BucketPolicyDeny_UserAgrnt() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:UserAgent",Arrays.asList("java/1.8.0_92"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","aws:Referer",Arrays.asList("java/1.8.0_92"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("User-Agent", "java/1.8.0_91");
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", params);
        assertEquals(403, putresult1.first().intValue());
        
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("User-Agent", "java/1.8.0_92");
        Pair<Integer, String> putresult2 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "world", params2);
        assertEquals(403, putresult2.first().intValue());
    }
    
    @Test
    public void test_Condition_PolicyDeny_BucketPolicyAllow_UserAgrnt() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:UserAgent",Arrays.asList("java/1.8.0_92"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","aws:UserAgent",Arrays.asList("java/1.8.0_92"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("User-Agent", "java/1.8.0_91");
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", params);
        assertEquals(403, putresult1.first().intValue());
        
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("User-Agent", "java/1.8.0_92");
        Pair<Integer, String> putresult2 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "world", params2);
        assertEquals(403, putresult2.first().intValue());
    }
    
    @Test
    public void test_Condition_PolicyAllow_BucketPolicyDeny_SourceIp() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("IpAddress","aws:SourceIp",Arrays.asList("192.168.1.1/24"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("X-Forwarded-For", "192.168.1.101");
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", params);
        assertEquals(403, putresult1.first().intValue());
        
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("Proxy-Client-IP", "192.168.1.101");
        Pair<Integer, String> putresult2 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "world", params2);
        assertEquals(403, putresult2.first().intValue());
    }
    
    @Test
    public void test_Condition_PolicyDeny_BucketPolicyAllow_SourceIp() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("IpAddress","aws:SourceIp",Arrays.asList("192.168.1.1/24"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("X-Forwarded-For", "192.168.1.101");
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", params);
        assertEquals(403, putresult1.first().intValue());
        
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("Proxy-Client-IP", "192.168.1.101");
        Pair<Integer, String> putresult2 = OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName, "world", params2);
        assertEquals(403, putresult2.first().intValue());
    }
    
    @Test
    public void test_Condition_PolicyAllow_BucketPolicyDeny_SecureTranport() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("true")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("Bool","aws:SecureTransport",Arrays.asList("true"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put("https", signVersion, jettyHttpsPort, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", null);
        assertEquals(403, putresult1.first().intValue());
        AssertAccessDeniedStringBucketPolicy(putresult1.second());
        
    }
    
    @Test
    public void test_Condition_PolicyDeny_BucketPolicyAllow_SecureTranport() {
        String bucketName=bucketName1;
        String objectName="conditions.txt";
        
        // iam policy 允许
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("true")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutObject"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket policy 允许
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("Bool","aws:SecureTransport",Arrays.asList("true"))); 
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),conditions2);
        System.out.println(bucketpolicyString);
        
        // 创建bucket policy
        OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        
        Pair<Integer, String> putresult1 = OOSInterfaceTestUtils.Object_Put("https", signVersion, jettyHttpsPort, user1accessKey1, user1secretKey1, bucketName,objectName, "hello", null);
        assertEquals(403, putresult1.first().intValue());
        AssertAccessDeniedStringIAM(putresult1.second(), "PutObject", user1Name, bucketName+"/"+objectName);
    }
    
    @Test
    public void test_BucketACLPublic() {
        String bucketName=bucketName1;
        String objectName="publicbucket1.txt";
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "public-read-write");
        Pair<Integer, String> putBucket=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null, null, null, null, params);
        assertEquals(200, putBucket.first().intValue());
        
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"123", null);
        assertEquals(200, putresult1.first().intValue());
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(200, getresult1.first().intValue());
        
        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(204, delresult1.first().intValue());
        
        Pair<Integer, String> postresult1=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"123", null);
        assertEquals(204, postresult1.first().intValue());
        
        String objectName3="des.txt";
        Pair<Integer, String> copyresult1=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,objectName3,null);
        assertEquals(200, copyresult1.first().intValue()); 
        
        String objectName2="mulit";
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_CopyPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,2,objectName,null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", getCopyPartEtag(uploadPartResult2.second()));
        
        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId,null);
        assertEquals(200, ListPartResult.first().intValue());   
        assertTrue(ListPartResult.second().contains("ListPartsResult"));
         
        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId, partEtagMap,null);
        assertEquals(200, completeResult.first().intValue()); 
        
        int headresult1=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName2,null);
        assertEquals(200, headresult1);
        
        
        
        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId, null);
        assertEquals(204, aborteResult.first().intValue());  
        
    }
    
    @Test
    public void test_BucketACLReadOnly() {
        String bucketName="yx-bucket-1";
        String objectName="readOnlybucket1.txt";
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "public-read");
        Pair<Integer, String> putBucket=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null, null, null, null, params);
        assertEquals(200, putBucket.first().intValue());
        
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"123", null);
        assertEquals(403, putresult1.first().intValue());
        
        Pair<Integer, String> rootputresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,"123", null);
        assertEquals(200, rootputresult1.first().intValue());
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(200, getresult1.first().intValue());
        
        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, delresult1.first().intValue());
        
        Pair<Integer, String> postresult1=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"123", null);
        assertEquals(403, postresult1.first().intValue());
        
        String objectName3="des.txt";
        Pair<Integer, String> copyresult1=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,objectName3,null);
        assertEquals(403, copyresult1.first().intValue()); 
        
        String objectName2="mulit";
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,null);
        assertEquals(403, initresult1.first().intValue()); 
        
        Pair<Integer, String> rootinitresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName2,null);
        assertEquals(200, rootinitresult1.first().intValue());
        
        String uploadId=getMultipartUploadId(rootinitresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,1,"uploadpart1",null);
        assertEquals(403, uploadPartResult1.first().intValue()); 
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_CopyPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,2,objectName,null);
        assertEquals(403, uploadPartResult2.first().intValue()); 
        
        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId,null);
        assertEquals(200, ListPartResult.first().intValue());   
        assertTrue(ListPartResult.second().contains("ListPartsResult"));
         
        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId, partEtagMap,null);
        assertEquals(403, completeResult.first().intValue()); 
        
        int headresult1=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(200, headresult1);

        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId, null);
        assertEquals(403, aborteResult.first().intValue()); 
    }
    
    @Test
    public void test_composite1() {
        // iam 允许所有操作
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket设置为只读
        String bucketName=bucketName1;
        String objectName="1.txt";
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "public-read");
        OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null, null, null, null, params);

        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"123", null);
        assertEquals(200, putresult1.first().intValue());
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(200, getresult1.first().intValue());
        
        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(204, delresult1.first().intValue());
        
        Pair<Integer, String> postresult1=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"123", null);
        assertEquals(204, postresult1.first().intValue());
        
        String objectName3="des.txt";
        Pair<Integer, String> copyresult1=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,objectName3,null);
        assertEquals(200, copyresult1.first().intValue()); 
        
        String objectName2="mulit";
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_CopyPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,2,objectName,null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        String etag=getCopyPartEtag(uploadPartResult2.second());
        partEtagMap.put("2", etag);
        
        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId,null);
        assertEquals(200, ListPartResult.first().intValue());   
        assertTrue(ListPartResult.second().contains("ListPartsResult"));
         
        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId, partEtagMap,null);
        assertEquals(200, completeResult.first().intValue()); 
        
        int headresult1=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName2,null);
        assertEquals(200, headresult1);
        
        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId, null);
        assertEquals(204, aborteResult.first().intValue());  
        
    }
    
    @Test
    public void test_composite2() {
        // iam 不允许删除操作
        String policyName="iamPolicy";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:Delete*","oos:Abort*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // bucket设置为公有
        String bucketName="yx-bucket-1";
        String objectName="publicbucket1.txt";
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "public-read-write");
        OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null, null, null, null, params);
        
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"123", null);
        assertEquals(200, putresult1.first().intValue());
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(200, getresult1.first().intValue());
        
        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, delresult1.first().intValue());
        
        Pair<Integer, String> postresult1=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"123", null);
        assertEquals(204, postresult1.first().intValue());
        
        String objectName3="des.txt";
        Pair<Integer, String> copyresult1=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,objectName3,null);
        assertEquals(200, copyresult1.first().intValue()); 
        
        String objectName2="mulit";
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_CopyPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,2,objectName,null);
        assertEquals(200, uploadPartResult2.first().intValue()); 
        partEtagMap.put("2", getCopyPartEtag(uploadPartResult2.second()));
        
        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId,null);
        assertEquals(200, ListPartResult.first().intValue());   
        assertTrue(ListPartResult.second().contains("ListPartsResult"));
         
        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId, partEtagMap,null);
        assertEquals(200, completeResult.first().intValue()); 
        
        int headresult1=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName2,null);
        assertEquals(200, headresult1);
        
        
        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId, null);
        assertEquals(403, aborteResult.first().intValue());  
    }
    
    @Test
    public void test_composite3() {
        // iam 允许IP范围内所有操作 
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24"))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        // bucketpolicy不允许putObject操作
        String bucketName=bucketName1;
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,"Principal",principals,"Action",Arrays.asList("s3:PutObject"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        String objectName="first.txt";
        
        // 创建bucket policy
        
        Pair<Integer, String> putBucketPlocy=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        assertEquals(200, putBucketPlocy.first().intValue());
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("X-Forwarded-For", "192.168.1.101");
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"123", params);
        assertEquals(403, putresult1.first().intValue());
        
        Pair<Integer, String> rootputresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,"123", null);
        assertEquals(200, rootputresult1.first().intValue());
        
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("X-Forwarded-For", "192.168.1.101");
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,params2);
        assertEquals(200, getresult1.first().intValue());
        
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("X-Forwarded-For", "192.168.1.101");
        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,params3);
        assertEquals(204, delresult1.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("X-Forwarded-For", "192.168.1.101");
        Pair<Integer, String> postresult1=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"123", params4);
        assertEquals(403, postresult1.first().intValue());
        
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("X-Forwarded-For", "192.168.1.101");
        String objectName3="des.txt";
        Pair<Integer, String> copyresult1=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,objectName3,params5);
        assertEquals(403, copyresult1.first().intValue()); 
        
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("X-Forwarded-For", "192.168.1.101");
        String objectName2="mulit";
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,params6);
        assertEquals(403, initresult1.first().intValue()); 
        
        Pair<Integer, String> rootinitresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName2,null);
        assertEquals(200, rootinitresult1.first().intValue());
        
        String uploadId=getMultipartUploadId(rootinitresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        HashMap<String, String> params7=new HashMap<String, String>();
        params7.put("X-Forwarded-For", "192.168.1.101");
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,1,"uploadpart1",params7);
        assertEquals(403, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> rootputresult2=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, objectName,"123", null);
        assertEquals(200, rootputresult2.first().intValue());
        HashMap<String, String> params8=new HashMap<String, String>();
        params8.put("X-Forwarded-For", "192.168.1.101");
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_CopyPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,2,objectName,params8);
        assertEquals(403, uploadPartResult2.first().intValue()); 
        
        HashMap<String, String> params9=new HashMap<String, String>();
        params9.put("X-Forwarded-For", "192.168.1.101");
        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId,params9);
        assertEquals(200, ListPartResult.first().intValue());   
        assertTrue(ListPartResult.second().contains("ListPartsResult"));
         
        HashMap<String, String> params10=new HashMap<String, String>();
        params10.put("X-Forwarded-For", "192.168.1.101");
        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId, partEtagMap,params10);
        assertEquals(403, completeResult.first().intValue()); 
        
        HashMap<String, String> params11=new HashMap<String, String>();
        params11.put("X-Forwarded-For", "192.168.1.101");
        int headresult1=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,params11);
        assertEquals(200, headresult1);

        HashMap<String, String> params12=new HashMap<String, String>();
        params12.put("X-Forwarded-For", "192.168.1.101");
        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId, params12);
        assertEquals(204, aborteResult.first().intValue()); 
        
    }
    
    @Test
    public void test_composite4() {
        // iam 允许user1不允许get操作
        String policyName="iamPolicy";
        List<Condition> conditions1 = new ArrayList<Condition>();
        conditions1.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(user1Name))); 
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:*Get*","oos:*List*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions1);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

        // bucketpolicy允许Object*操作
        String bucketName=bucketName1;
        String objectName="afgvsd";
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String bucketpolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:*"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName+"/*"),null);
        System.out.println(bucketpolicyString);
        
        Pair<Integer, String> putBucketPlocy=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, bucketpolicyString, null);
        assertEquals(200, putBucketPlocy.first().intValue());
        
        Pair<Integer, String> putresult1=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"123", null);
        assertEquals(200, putresult1.first().intValue());
        
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(403, getresult1.first().intValue());
        
        Pair<Integer, String> getresult2=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyport, user2accessKey, user2secretKey, bucketName,objectName,null);
        assertEquals(200, getresult2.first().intValue());
        
        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName,null);
        assertEquals(204, delresult1.first().intValue());
        
        Pair<Integer, String> postresult1=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,"123", null);
        assertEquals(204, postresult1.first().intValue());
        
        String objectName3="des.txt";
        Pair<Integer, String> copyresult1=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName,objectName3,null);
        assertEquals(403, copyresult1.first().intValue()); 
        
        String objectName2="mulit";
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
        
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
        
        Pair<Integer, String> uploadPartResult2=OOSInterfaceTestUtils.Object_CopyPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,2,objectName,null);
        assertEquals(403, uploadPartResult2.first().intValue()); 
       
        Pair<Integer, String> uploadPartResult3=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, objectName2,uploadId,2,"uploadpart2",null);
        assertEquals(200, uploadPartResult3.first().intValue()); 
        partEtagMap.put("2", uploadPartResult3.second());
        
        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId,null);
        assertEquals(403, ListPartResult.first().intValue());   
       
        Pair<Integer, String> ListPartResult2=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyport,user2accessKey, user2secretKey, bucketName,objectName2, uploadId,null);
        assertEquals(200, ListPartResult2.first().intValue());   
        assertTrue(ListPartResult2.second().contains("ListPartsResult"));
         
        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId, partEtagMap,null);
        assertEquals(200, completeResult.first().intValue()); 
        
        int headresult1=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName,objectName2,null);
        assertEquals(403, headresult1);
        
        int headresult2=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyport, user2accessKey, user2secretKey, bucketName,objectName2,null);
        assertEquals(200, headresult2);
        
        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1, bucketName,objectName2, uploadId, null);
        assertEquals(204, aborteResult.first().intValue());  
 
    }
    
    public void AssertAccessDeniedStringIAM(String xml,String methodString,String userName,String resource) {
        try {
            JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
            assertEquals("AccessDenied", error.get("Code"));
            assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+userName+" is not authorized to perform: oos:"+methodString+" on resource: arn:ctyun:oos::3rmoqzn03g6ga:"+resource+".", error.get("Message"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }
    
    public void AssertAccessDeniedStringBucketPolicy(String xml) {
        try {
            JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
            assertEquals("AccessDenied", error.get("Code"));
            assertEquals("Access Denied", error.get("Message"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }
    
    public String getMultipartUploadId(String xml) {
        String uploadId="";
        try {
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = doc.getRootElement();
            @SuppressWarnings("unchecked")
            List<Element> secondLevel=root.getChildren();
            
           uploadId=secondLevel.get(2).getText();
           System.out.println("uploadId="+uploadId);
        } catch (Exception e) {
            e.printStackTrace();;
        }
        
        return uploadId;
    }
    
    public String getCopyPartEtag(String xml) {
        String etag="";
        try {
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = doc.getRootElement();
            @SuppressWarnings("unchecked")
            List<Element> secondLevel=root.getChildren();
            
            etag=secondLevel.get(1).getText();
        } catch (Exception e) {
            e.printStackTrace();;
        }
        
        return etag;
    }

}
