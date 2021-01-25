package cn.ctyun.oos.iam.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.apache.hadoop.hdfs.server.namenode.nn_005fbrowsedfscontent_jsp;
import org.eclipse.jetty.util.UrlEncoded;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.utils.V2SignClient;
import cn.ctyun.oos.utils.V4SignClient;
import cn.ctyun.oos.utils.api.CloudTrailAPITestUtils;
import cn.ctyun.oos.utils.api.OOSAPITestUtils;
import cn.ctyun.oos.utils.env.CleanTable;
import common.tuple.Pair;

public class PolicyVariableTest {
    
    public static final String OOS_IAM_DOMAIN="https://oos-cd-iam.ctyunapi.cn:9460/";
    public static final String OOS_CLOUDTRAIL_DOMAIN="https://oos-cd-cloudtrail.ctyunapi.cn:9458/";
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    public static final String regionName="cd";
    
    private static String ownerName = "root_user1@test.com";
    public static final String accessKey="userak1";
    public static final String secretKey="usersk1";
    
    public static final String user1Name="test1_1111@com.cn+2=-,";
    public static final String user2Name="test2";
    public static final String user3Name="test1";
    
    public static final String user1accessKey="abcdefghijklmnop";
    public static final String user1secretKey="cccccccccccccccc";
    public static final String user2accessKey="qrstuvwxyz0000000";
    public static final String user2secretKey="bbbbbbbbbbbbbbbbbb";
    public static final String user3accessKey="sepcak111111111111";
    public static final String user3secretKey="sepcsk111111111111";
    
    public static String accountId="3fdmxmc3pqvmp";
    public static String mygroupName="mygroup";

    public static final String cloudtrailBucket="cloudtrail-bucket";
    
    
    
    public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        
    }

    @Before
    public void setUp() throws Exception {
        CleanTable.Clean_Owner();
        CleanTable.Clean_IAM();
        CleanTable.Clean_OOS();
        CleanAndCreateUser();   
    }

    public static void CleanAndCreateUser() throws Exception {
        
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
        user1.userId="userid1";
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
        aksk1.accessKey=user1accessKey;
        aksk1.setSecretKey(user1secretKey);
        metaClient.akskInsert(aksk1);
        user1.accessKeys = new ArrayList<>();
        user1.accessKeys.add(aksk1.accessKey);
        
        HBaseUtils.put(user1);
        
        String UserName2=user2Name;
        User user2=new User();
        user2.accountId=accountId;
        user2.userName=UserName2;
        user2.userId="userid2";
        user2.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user2);
            assertTrue(success);
        } catch (IOException e) {
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
        user3.userId="userid3";
        user3.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user3);
            assertTrue(success);
        } catch (IOException e) {
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
          
        OOSAPITestUtils.Bucket_Put("http", "oos-cd.ctyunapi.cn", 80, "V2", "cd", accessKey, secretKey, cloudtrailBucket, "Local", null, null, null, null);
    }
    
    @Test
    /*
     * user/${ctyun:username}
     */
    public void test_iam_user_Match() {
        String policyName="usermatch1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/${ctyun:username}"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag1=new Pair<String, String>();
        tag1.first("team");
        tag1.second("test");
        tags.add(tag1);
        String policyName2="mypolicy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"abc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user2accessKey, user2secretKey, user2Name+"abc", tags, policyName2, policyString2, accountId);
        
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"bbc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user2accessKey, user2secretKey, user2Name+"bbc", tags, policyName2, policyString2, accountId);
        
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"abbc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user2accessKey, user2secretKey, user2Name+"abbc", tags, policyName2, policyString2, accountId);
        
        AllowActionResourceUser_NoCreateDelete(accessKey, secretKey, user1accessKey, user1secretKey, user1Name, tags, policyName2, policyString2, accountId);
        AllowActionResourceUser_NoCreateDelete(accessKey, secretKey, user2accessKey, user2secretKey, user2Name, tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey, user1secretKey, user2Name, tags, policyName2, policyString2, accountId);

    }
    
    @Test
    /*
     * user/${ctyun:username}abc精确匹配
     */
    public void test_iam_user_ExactMatch() {
        String policyName="iam_user_ExactMatch";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/${ctyun:username}abc"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag1=new Pair<String, String>();
        tag1.first("team");
        tag1.second("test");
        tags.add(tag1);
        String policyName2="mypolicy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);

        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey, user1secretKey, user1Name, tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user2accessKey, user2secretKey, user2Name, tags, policyName2, policyString2, accountId);
        
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"abc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"abc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey, user1secretKey, user2Name+"abc", tags, policyName2, policyString2, accountId);
        
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"bbc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user2accessKey, user2secretKey, user2Name+"bbc", tags, policyName2, policyString2, accountId);
        
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"abbc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user2accessKey, user2secretKey, user2Name+"abbc", tags, policyName2, policyString2, accountId);
       
    }
    
    @Test
    /*
     * user/${ctyun:username}?bc
     */
    public void test_iam_user_FuzzyMatch1() {
        String policyName="FuzzyMatch1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/${ctyun:username}?bc"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag1=new Pair<String, String>();
        tag1.first("team");
        tag1.second("test");
        tags.add(tag1);
        String policyName2="mypolicy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);

        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey, user1secretKey, user1Name, tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user2accessKey, user2secretKey, user2Name, tags, policyName2, policyString2, accountId);
        
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"abc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"abc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey, user1secretKey, user2Name+"abc", tags, policyName2, policyString2, accountId);
        
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"bbc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"bbc", tags, policyName2, policyString2, accountId);
        
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"abbc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user2accessKey, user2secretKey, user2Name+"abbc", tags, policyName2, policyString2, accountId);

    }
    
    @Test
    /*
     * user/${ctyun:username}*bc
     */
    public void test_iam_user_FuzzyMatch2() {
        String policyName="FuzzyMatch2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/${ctyun:username}*bc"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag1=new Pair<String, String>();
        tag1.first("team");
        tag1.second("test");
        tags.add(tag1);
        String policyName2="mypolicy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);

        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey, user1secretKey, user1Name, tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user2accessKey, user2secretKey, user2Name, tags, policyName2, policyString2, accountId);
        
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"abc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"abc", tags, policyName2, policyString2, accountId);
        
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"bbc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"bbc", tags, policyName2, policyString2, accountId);
        
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"abbc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"abbc", tags, policyName2, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey, user1secretKey, user2Name+"abbc", tags, policyName2, policyString2, accountId);
        
    }
    
    @Test
    public void test_iam_group_Match() {
        String policyName="iam_group_Match";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/${ctyun:username}"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="myattach";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String myuser="test100";
        IAMInterfaceTestUtils.CreateUser(accessKey, secretKey, myuser, 200);
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name, myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name, myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey, user1secretKey, user2Name, myuser, accountId, policyName2, policyString2);
        
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"dev", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey,  user2accessKey, user2secretKey, user2Name+"dev", myuser, accountId, policyName2, policyString2);
        
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"dav", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey,  user2accessKey, user2secretKey, user2Name+"dav", myuser, accountId, policyName2, policyString2);

        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"d", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey,  user2accessKey, user2secretKey, user2Name+"d", myuser, accountId, policyName2, policyString2);

    }
    
    @Test
    public void test_iam_group_ExactMatch() {
        String policyName="iam_group_ExactMatch";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/${ctyun:username}dev"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="myattach";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String myuser="test100";
        IAMInterfaceTestUtils.CreateUser(accessKey, secretKey, myuser, 200);
        
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey, user1secretKey, user1Name, myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey,  user2accessKey, user2secretKey, user2Name, myuser, accountId, policyName2, policyString2);
      
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"dev", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"dev", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey, user1secretKey, user2Name+"dev", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"Dev", myuser, accountId, policyName2, policyString2);
        
        
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"dav", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey,  user2accessKey, user2secretKey, user2Name+"dav", myuser, accountId, policyName2, policyString2);

        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"d", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey,  user2accessKey, user2secretKey, user2Name+"d", myuser, accountId, policyName2, policyString2);
        
    }
    
    @Test
    public void test_iam_group_FuzzyMatch1() {
        String policyName="iam_group_FuzzyMatch1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/${ctyun:username}d?v"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="myattach";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String myuser="test100";
        IAMInterfaceTestUtils.CreateUser(accessKey, secretKey, myuser, 200);
        
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey, user1secretKey, user1Name, myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey,  user2accessKey, user2secretKey, user2Name, myuser, accountId, policyName2, policyString2);
      
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"dev", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"dev", myuser, accountId, policyName2, policyString2);
          
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"dav", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"dav", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey, user1secretKey, user2Name+"dav", myuser, accountId, policyName2, policyString2);
        
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"d", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey,  user2accessKey, user2secretKey, user2Name+"d", myuser, accountId, policyName2, policyString2);        
    }
    
    @Test
    public void test_iam_group_FuzzyMatch2() {
        String policyName="iam_group_FuzzyMatch2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":group/${ctyun:username}d*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="myattach";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String myuser="test100";
        IAMInterfaceTestUtils.CreateUser(accessKey, secretKey, myuser, 200);
        
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey, user1secretKey, user1Name, myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey,  user2accessKey, user2secretKey, user2Name, myuser, accountId, policyName2, policyString2);
      
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"dev", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"dev", myuser, accountId, policyName2, policyString2);
        
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"dav", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"dav", myuser, accountId, policyName2, policyString2);
        
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"d", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"d", myuser, accountId, policyName2, policyString2);
        IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey, user1secretKey, user2Name+"d", myuser, accountId, policyName2, policyString2);
        
    }
    
    @Test
    public void test_iam_policy_Match() {
        String policyName="iam_policy_Match";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":policy/${ctyun:username}"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);

        IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name, policyString2, accountId);
        IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user2Name, policyString2, accountId);
        
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"abc", policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user2Name+"abc", policyString2, accountId);
        
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"bbc", policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user2Name+"bbc", policyString2, accountId);
        
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"abbc", policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user2Name+"abbc", policyString2, accountId);

    }
    
    @Test
    public void test_iam_policy_ExactMatch() {
        String policyName="iam_policy_Match";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":policy/${ctyun:username}abc"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);

        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user1Name, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user2Name, policyString2, accountId);
        
        IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"abc", policyString2, accountId);
        IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"abc", policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user2Name+"abc", policyString2, accountId);
        
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"bbc", policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user2Name+"bbc", policyString2, accountId);
        
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"abbc", policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user2Name+"abbc", policyString2, accountId);
        
    }
    
    @Test
    public void test_iam_policy_FuzzyMatch1() {
        String policyName="iam_policy_Match";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":policy/${ctyun:username}?bc"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);

        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user1Name, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user2Name, policyString2, accountId);
        
        IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"abc", policyString2, accountId);
        IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"abc", policyString2, accountId);
        
        IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"bbc", policyString2, accountId);
        IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"bbc", policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user2Name+"bbc", policyString2, accountId);
        
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user1Name+"abbc", policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user2Name+"abbc", policyString2, accountId);

    }
    
    @Test
    public void test_iam_policy_FuzzyMatch2() {
        String policyName="iam_policy_Match";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":policy/${ctyun:username}*bc"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);

        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user1Name, policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey, user1secretKey, user2Name, policyString2, accountId);
        
        IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"abc", policyString2, accountId);
        IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"abc", policyString2, accountId);
        
        IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"bbc", policyString2, accountId);
        IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"bbc", policyString2, accountId);
        
        IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, null, user1accessKey, user1secretKey, user1Name+"abbc", policyString2, accountId);
        IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, null, user2accessKey, user2secretKey, user2Name+"abbc", policyString2, accountId);
        IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey,  user1accessKey, user1secretKey, user2Name+"abbc", policyString2, accountId);

    }
    
    @Test
    public void test_iam_mfa_Match() {
        String policyName="iam_mfa_Match";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":mfa/${ctyun:username}"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey, user1secretKey, accountId, user1Name);
        IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user2accessKey, user2secretKey, accountId, user2Name);
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey,user1accessKey, user1secretKey, accountId, user2Name);
        
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey, user1secretKey, accountId, user1Name+"abc");
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user2accessKey, user2secretKey, accountId, user2Name+"abc");
        
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey, user1secretKey, accountId, user1Name+"bbc");
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user2accessKey, user2secretKey, accountId, user2Name+"bbc");
        
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey, user1secretKey, accountId, user1Name+"abbc");
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user2accessKey, user2secretKey, accountId, user2Name+"abbc");
                
    }
    
    @Test
    public void test_iam_mfa_ExactMatch() {
        String policyName="iam_mfa_ExactMatch";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":mfa/${ctyun:username}abc"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey, user1secretKey, accountId, user1Name);
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user2accessKey, user2secretKey, accountId, user2Name);
        
        IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey, user1secretKey, accountId, user1Name+"abc");
        IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user2accessKey, user2secretKey, accountId, user2Name+"abc");
        
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey, user1secretKey, accountId, user1Name+"bbc");
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user2accessKey, user2secretKey, accountId, user2Name+"bbc");
        
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey, user1secretKey, accountId, user1Name+"abbc");
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user2accessKey, user2secretKey, accountId, user2Name+"abbc");
        
     }
    
    @Test
    public void test_iam_mfa_FuzzyMatch1() {
        String policyName="iam_mfa_FuzzyMatch1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":mfa/${ctyun:username}?bc"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey, user1secretKey, accountId, user1Name);
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user2accessKey, user2secretKey, accountId, user2Name);
        
        IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey, user1secretKey, accountId, user1Name+"abc");
        IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user2accessKey, user2secretKey, accountId, user2Name+"abc");
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey, user1secretKey, accountId, user2Name+"abc");
        
        IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey, user1secretKey, accountId, user1Name+"bbc");
        IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user2accessKey, user2secretKey, accountId, user2Name+"bbc");
        
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey, user1secretKey, accountId, user1Name+"abbc");
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user2accessKey, user2secretKey, accountId, user2Name+"abbc");
        
    }
    
    @Test
    public void test_iam_mfa_FuzzyMatch2() {
        String policyName="iam_mfa_FuzzyMatch1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":mfa/${ctyun:username}*bc"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey, user1secretKey, accountId, user1Name);
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user2accessKey, user2secretKey, accountId, user2Name);
        
        IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey, user1secretKey, accountId, user1Name+"abc");
        IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user2accessKey, user2secretKey, accountId, user2Name+"abc");
        
        IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey, user1secretKey, accountId, user1Name+"bbc");
        IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user2accessKey, user2secretKey, accountId, user2Name+"bbc");
        IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey, user1secretKey, accountId, user2Name+"bbc");
        
        IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey, user1secretKey, accountId, user1Name+"abbc");
        IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user2accessKey, user2secretKey, accountId, user2Name+"abbc");

    }
    
    @Test
    public void test_cloudtrial_trail_Match() {
        String policyName="cloudtrial_trail_Match";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/${ctyun:username}"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        AllowActionResourceTrail(user3accessKey, user3secretKey, user3Name);
        AllowActionResourceTrail(user2accessKey, user2secretKey, user2Name);
        DenyActionResourceTrail(accessKey, secretKey, user3accessKey, user3secretKey, user2Name);
        
        DenyActionResourceTrail(accessKey, secretKey, user3accessKey, user3secretKey, user3Name+"abc");
        DenyActionResourceTrail(accessKey, secretKey, user2accessKey, user2secretKey, user2Name+"abc");
        
        DenyActionResourceTrail(accessKey, secretKey, user3accessKey, user3secretKey, user3Name+"bbc");
        DenyActionResourceTrail(accessKey, secretKey, user2accessKey, user2secretKey, user2Name+"bbc");
        
        DenyActionResourceTrail(accessKey, secretKey, user3accessKey, user3secretKey, user3Name+"abbc");
        DenyActionResourceTrail(accessKey, secretKey, user2accessKey, user2secretKey, user2Name+"abbc");
        
    }
    
    @Test
    public void test_cloudtrial_trail_ExactMatch() {
        String policyName="cloudtrial_trail_ExactMatch";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/${ctyun:username}abc"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        
        DenyActionResourceTrail(accessKey, secretKey, user3accessKey, user3secretKey, user3Name);
        DenyActionResourceTrail(accessKey, secretKey, user2accessKey, user2secretKey, user2Name);
        
        AllowActionResourceTrail(user3accessKey, user3secretKey, user3Name+"abc");
        AllowActionResourceTrail(user2accessKey, user2secretKey, user2Name+"abc");
        DenyActionResourceTrail(accessKey, secretKey, user3accessKey, user3secretKey, user2Name+"abc");
        
        DenyActionResourceTrail(accessKey, secretKey, user3accessKey, user3secretKey, user3Name+"bbc");
        DenyActionResourceTrail(accessKey, secretKey, user2accessKey, user2secretKey, user2Name+"bbc");
        
        DenyActionResourceTrail(accessKey, secretKey, user3accessKey, user3secretKey, user3Name+"abbc");
        DenyActionResourceTrail(accessKey, secretKey, user2accessKey, user2secretKey, user2Name+"abbc");

    }
    
    @Test
    public void test_cloudtrial_trail_FuzzyMatch1() {
        String policyName="cloudtrial_trail_FuzzyMatch1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/${ctyun:username}?bc"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        
        DenyActionResourceTrail(accessKey, secretKey, user3accessKey, user3secretKey, user3Name);
        DenyActionResourceTrail(accessKey, secretKey, user2accessKey, user2secretKey, user2Name);
        
        AllowActionResourceTrail(user3accessKey, user3secretKey, user3Name+"abc");
        AllowActionResourceTrail(user2accessKey, user2secretKey, user2Name+"abc");
         
        AllowActionResourceTrail(user3accessKey, user3secretKey, user3Name+"bbc");
        AllowActionResourceTrail(user2accessKey, user2secretKey, user2Name+"bbc");
        DenyActionResourceTrail(accessKey, secretKey, user3accessKey, user3secretKey, user2Name+"bbc");

        DenyActionResourceTrail(accessKey, secretKey, user3accessKey, user3secretKey, user3Name+"abbc");
        DenyActionResourceTrail(accessKey, secretKey, user2accessKey, user2secretKey, user2Name+"abbc");

    }
    
    @Test
    public void test_cloudtrial_trail_FuzzyMatch2() {
        String policyName="cloudtrial_trail_FuzzyMatch1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/${ctyun:username}*bc"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        DenyActionResourceTrail(accessKey, secretKey, user1accessKey, user1secretKey, user3Name);
        DenyActionResourceTrail(accessKey, secretKey, user2accessKey, user2secretKey, user2Name);
        
        AllowActionResourceTrail(user3accessKey, user3secretKey, user3Name+"abc");
        AllowActionResourceTrail(user2accessKey, user2secretKey, user2Name+"abc");
        
        
        AllowActionResourceTrail(user3accessKey, user3secretKey, user3Name+"bbc");
        AllowActionResourceTrail(user2accessKey, user2secretKey, user2Name+"bbc");
        
        AllowActionResourceTrail(user3accessKey, user3secretKey, user3Name+"abbc");
        AllowActionResourceTrail(user2accessKey, user2secretKey, user2Name+"abbc");
        DenyActionResourceTrail(accessKey, secretKey, user3accessKey, user3secretKey, user2Name+"abbc");
       
    }
    
    @Test
    public void test_cloudtrial_error() throws JSONException {
        String policyName="cloudtrial_trail_Match";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("cloudtrail:*"),"Resource",Arrays.asList("arn:ctyun:cloudtrail::"+accountId+":trail/${ctyun:username}"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        
        String trailName=user1Name;
        String accessKey=user1accessKey;
        String secretKey=user1secretKey;
        Pair<Integer, String> createtrail=CloudTrailAPITestUtils.CreateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, cloudtrailBucket, true, null);
        assertEquals(400, createtrail.first().intValue());
        JSONObject jo=ParseErrorToJson(createtrail.second());
        assertEquals("InvalidTrailNameException", jo.getString("Code"));
        assertEquals("Trail name or ARN can only contain uppercase letters, lowercase letters, numbers, periods (.), hyphens (-), and underscores (_).",jo.getString("Message"));
        assertEquals(user1Name, jo.getString("Resource"));
        System.out.println();
       
    }
    
    @Test
    public void test_oos_bucket_Match() {
        String policyName="oos_bucket_Match";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":${ctyun:username}"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        AllowActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, user3Name);
        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, user2Name);
        AllowActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, user2Name);

        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, "aa"+user3Name);
        DenyActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, "aa"+user2Name);
        
        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user1secretKey, "aab"+user3Name);
        DenyActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, "aab"+user2Name);
        
        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user1secretKey, "aabb"+user3Name);
        DenyActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, "aabb"+user2Name);
 
    }
    
    @Test
    public void test_oos_bucket_ExactMatch() {
        String policyName="oos_bucket_ExactMatch";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":aa${ctyun:username}"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, user3Name);
        DenyActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, user2Name);
        
        AllowActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, "aa"+user3Name);
        AllowActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, "aa"+user2Name);
//        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, "aa"+user2Name);
        
        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, "aab"+user3Name);
        DenyActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, "aab"+user2Name);
        
        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, "aabb"+user3Name);
        DenyActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, "aabb"+user2Name);
        
    }
    
    @Test
    public void test_oos_bucket_FuzzyMatch1() {
        String policyName="oos_bucket_FuzzyMatch1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":aa?b${ctyun:username}"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        
        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, user3Name);
        DenyActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, user2Name);
        
        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, "aa"+user3Name);
        DenyActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, "aa"+user2Name);
        
        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, "aab"+user3Name);
        DenyActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, "aab"+user2Name);
        
        AllowActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, "aabb"+user3Name);
        AllowActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, "aabb"+user2Name);
//        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, "aabb"+user2Name);
        
    }
    
    @Test
    public void test_oos_bucket_FuzzyMatch2() {
        String policyName="oos_bucket_FuzzyMatch2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":aa*b${ctyun:username}"),null);
        
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        
        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, user3Name);
        DenyActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, user2Name);
        
        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, "aa"+user3Name);
        DenyActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, "aa"+user2Name);
        
        AllowActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, "aab"+user3Name);
        AllowActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, "aab"+user2Name);
//        DenyActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, "aab"+user2Name);
        
        AllowActionResourceBucket(accessKey, secretKey, user3accessKey, user3secretKey, "aabb"+user3Name);
        AllowActionResourceBucket(accessKey, secretKey, user2accessKey, user2secretKey, "aabb"+user2Name);

    }
    
    @Test
    public void test_bucket_error() throws JSONException {
        String policyName="oos_bucket_FuzzyMatch2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":aa*b${ctyun:username}"),null);
        
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        String host="oos-cd.ctyunapi.cn";
        String httpOrHttps="https";
        int jettyPort=8444;
        String signVersion="V2";
        String bucketName=user1Name;
        
        // 创建bucket  
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, V4SignClient.urlEncode(bucketName, false), null, null, null, null, null);
        assertEquals(400, createbucket2.first().intValue());
        JSONObject jo=ParseErrorToJson(createbucket2.second());
        assertEquals("InvalidBucketName", jo.getString("Code"));
        assertEquals("the bucket name is:"+bucketName,jo.getString("Message"));
        assertEquals("/-", jo.getString("Resource"));

    }
    
    @Test
    public void test_oos_objectPrex_Match() {
        String bucketName="yx-bucket-3";
        String policyName="oos_objectPrex_Match";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/${ctyun:username}/*"),null);
        
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        
        AllowActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user1Name+"/");
        DenyActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user2Name+"/");
        AllowActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"/");
        
        
        DenyActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user3Name+"_01/");
        DenyActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"_01/");
        
        DenyActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user3Name+"_02/");
        DenyActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"_02/");
        
        DenyActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user1Name+"01/");
        DenyActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"01/");
        
    }
    
    
    @Test
    public void test_oos_objectPrex_ExactMatch() {
        String bucketName="yx-bucket-3";
        String policyName="oos_objectPrex_Match";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/${ctyun:username}_01/*"),null);
        
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        

        DenyActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user1Name+"/");
        DenyActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"/");
        
        AllowActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user1Name+"_01/");
        DenyActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user2Name+"_01/");
        AllowActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"_01/");
        
        DenyActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user1Name+"_02/");
        DenyActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"_02/");
        
        DenyActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user1Name+"01/");
        DenyActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"01/");
        
    }
    
    @Test
    public void test_oos_objectPrex_FuzzyMatch1() {
        String bucketName="yx-bucket-3";
        String policyName="oos_objectPrex_FuzzyMatch1";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/${ctyun:username}_0?/*"),null);
        
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
        

        DenyActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user1Name+"/");
        DenyActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"/");

        AllowActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user1Name+"_01/");
        AllowActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"_01/");
        
        AllowActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user1Name+"_02/");
        AllowActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"_02/");
        DenyActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user2Name+"_02/");
        
        DenyActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user1Name+"01/");
        DenyActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"01/");
        
    }
    
    @Test
    public void test_oos_objectPrex_FuzzyMatch2() {
        String bucketName="yx-bucket-3";
        String policyName="oos_objectPrex_FuzzyMatch2";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName+"/${ctyun:username}*1/*"),null);
        
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

        DenyActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user1Name+"/");
        DenyActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"/");

        AllowActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user1Name+"_01/");
        AllowActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"_01/");
        
        DenyActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user1Name+"_02/");
        DenyActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"_02/");
        
        AllowActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user1Name+"01/");
        AllowActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"01/");
        DenyActionResourceObject(accessKey, secretKey, user1accessKey, user1secretKey, bucketName, user2Name+"_01/");
    }
    
    @Test
    public void test_variableError() {
        String policyName="test_variableError";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/${ctyun:username*}"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag1=new Pair<String, String>();
        tag1.first("team");
        tag1.second("test");
        tags.add(tag1);
        String policyName2="mypolicy";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);

        IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey, user1secretKey, user1Name, tags, policyName2, policyString2, accountId);
    }
    
    @Test
    public void test_listbucket_oosPrefix_StringLike_allow() {
       // String Like
       // 两个bucket。user1可以访问user1的，不可以访问user2的，user2可以访问user2的
        
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        String bucketName2="yx-bucket-4";
        
        String policyName="test_listbucket";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","oos:prefix",Arrays.asList("${ctyun:username}/*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null, null, null, null, null);
        assertEquals(200, createbucket2.first().intValue());
        System.out.println(createbucket2.second());
        
        // user1可以list自己的，不可以list别人的
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(200, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName2, user1Name+"/",null,null,null,null);
        assertEquals(403, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(403, listobjects3.first().intValue());
        
        Pair<Integer, String> listobject4=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user2accessKey, user2secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(403, listobject4.first().intValue());
        
    }
    
    @Test
    public void test_listbucket_oosPrefix_StringLike_deny() {
       // String Like
       // 两个bucket。user1可以访问user1的，不可以访问user2的，user2可以访问user2的
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        String bucketName2="yx-bucket-4";
        
        String policyName="test_listbucketDeny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","oos:prefix",Arrays.asList("${ctyun:username}/*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        System.out.println(policyString);
        
        String policyName2="test_listbucketallow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        System.out.println(policyString2);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(403, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(200, listobjects3.first().intValue());
        
        Pair<Integer, String> listobjects4=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, "abc/",null,null,null,null);
        assertEquals(200, listobjects4.first().intValue());
        
    }
    
    @Test
    public void test_listbucket_oosPrefix_StringNotLike_allow() {
       // String Not Like
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucket";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","oos:prefix",Arrays.asList("${ctyun:username}/*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(403, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(200, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, "abc/",null,null,null,null);
        assertEquals(200, listobjects3.first().intValue());
        
    }
    
    @Test
    public void test_listbucket_oosPrefix_StringNotLike_deny() {
       // String Not Like
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucketdeny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","oos:prefix",Arrays.asList("${ctyun:username}/*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_listbucketallow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        System.out.println(policyString2);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(200, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(403, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, "abc/",null,null,null,null);
        assertEquals(403, listobjects3.first().intValue());
        
    }
    
    
    @Test
    public void test_listbucket_oosPrefix_StringEqual_allow() {
       // String Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucket";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","oos:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(200, listobjects.first().intValue());
         
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(403, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(403, listobjects3.first().intValue());
    }
    
    @Test
    public void test_listbucket_oosPrefix_StringEqual_deny() {
       // String Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucketdeny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","oos:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_listbucketallow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        System.out.println(policyString2);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(403, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(200, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(200, listobjects3.first().intValue());
    }
    
    @Test
    public void test_listbucket_oosPrefix_StringNotEqual_allow() {
        // String Not Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucket";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","oos:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(403, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(200, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(200, listobjects3.first().intValue());
    }
    
    @Test
    public void test_listbucket_oosPrefix_StringNotEqual_deny() {
        // String Not Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucketdeny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","oos:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_listbucketallow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        System.out.println(policyString2);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(200, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(403, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(403, listobjects3.first().intValue());
    }
    
    @Test
    public void test_listbucket_oosPrefix_StringEqualIgnoreCase_allow() {
       // String Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucket";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","oos:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(200, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(403, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(200, listobjects3.first().intValue());
    }
    
    @Test
    public void test_listbucket_oosPrefix_StringEqualIgnoreCase_deny() {
       // String Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucketdeny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","oos:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_listbucketallow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        System.out.println(policyString2);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(403, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(200, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(403, listobjects3.first().intValue());
    }
    
    @Test
    public void test_listbucket_oosPrefix_StringNotEqualIgnoreCase_allow() {
        // String Not Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucket";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","oos:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(403, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(200, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(403, listobjects3.first().intValue());
        
    }
    
    @Test
    public void test_listbucket_oosPrefix_StringNotEqualIgnoreCase_deny() {
        // String Not Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucketdeny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","oos:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_listbucketallow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        System.out.println(policyString2);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(200, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(403, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(200, listobjects3.first().intValue());
    }
    
    @Test
    public void test_oosPrefix_notforobjectlevle() {
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName=user2Name;
        
        String policyName="test_listbucket2";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","oos:prefix",Arrays.asList("${ctyun:username}/*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
      
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
      
      
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket2.first().intValue());
        System.out.println(createbucket2.second());
      
        // user1可以list自己的，不可以list别人的
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user2accessKey, user2secretKey, bucketName,null);
        assertEquals(403, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user2accessKey, user2secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(200, listobjects2.first().intValue());
        
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, host, jettyPort, signVersion, regionName, user2accessKey, user2secretKey, bucketName, "/user2put.txt", "user2", null);
        assertEquals(403, putobject.first().intValue());
        
        int head=OOSAPITestUtils.Bucket_Head(httpOrHttps, host, jettyPort, signVersion, regionName, user2accessKey, user2secretKey, bucketName, null);
        assertEquals(403, head);
        
        DenyActionResourceObject(accessKey, secretKey, user2accessKey, user2secretKey, bucketName, user2Name+"/");
     
    }
    
    @Test
    public void test_listbucket_s3Prefix_StringLike_allow() {
       // String Like
       // 两个bucket。user1可以访问user1的，不可以访问user2的，user2可以访问user2的
        
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        String bucketName2="yx-bucket-4";
        
        String policyName="test_listbucket";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","s3:prefix",Arrays.asList("${ctyun:username}/*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null, null, null, null, null);
        assertEquals(200, createbucket2.first().intValue());
        System.out.println(createbucket2.second());
        
        // user1可以list自己的，不可以list别人的
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(200, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName2, user1Name+"/",null,null,null,null);
        assertEquals(403, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(403, listobjects3.first().intValue());
        
        Pair<Integer, String> listobject4=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user2accessKey, user2secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(403, listobject4.first().intValue());
        
    }
    
    @Test
    public void test_listbucket_s3Prefix_StringLike_deny() {
       // String Like
       // 两个bucket。user1可以访问user1的，不可以访问user2的，user2可以访问user2的
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        String bucketName2="yx-bucket-4";
        
        String policyName="test_listbucketDeny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","s3:prefix",Arrays.asList("${ctyun:username}/*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        System.out.println(policyString);
        
        String policyName2="test_listbucketallow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        System.out.println(policyString2);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(403, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(200, listobjects3.first().intValue());
        
        Pair<Integer, String> listobjects4=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, "abc/",null,null,null,null);
        assertEquals(200, listobjects4.first().intValue());
        
    }
    
    @Test
    public void test_listbucket_s3Prefix_StringNotLike_allow() {
       // String Not Like
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucket";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","s3:prefix",Arrays.asList("${ctyun:username}/*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(403, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(200, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, "abc/",null,null,null,null);
        assertEquals(200, listobjects3.first().intValue());
        
    }
    
    @Test
    public void test_listbucket_s3Prefix_StringNotLike_deny() {
       // String Not Like
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucketdeny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","s3:prefix",Arrays.asList("${ctyun:username}/*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_listbucketallow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        System.out.println(policyString2);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(200, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(403, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, "abc/",null,null,null,null);
        assertEquals(403, listobjects3.first().intValue());
        
    }
    
    
    @Test
    public void test_listbucket_s3Prefix_StringEqual_allow() {
       // String Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucket";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","s3:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(200, listobjects.first().intValue());
         
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(403, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(403, listobjects3.first().intValue());
    }
    
    @Test
    public void test_listbucket_s3Prefix_StringEqual_deny() {
       // String Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucketdeny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","s3:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_listbucketallow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        System.out.println(policyString2);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(403, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(200, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(200, listobjects3.first().intValue());
    }
    
    @Test
    public void test_listbucket_s3Prefix_StringNotEqual_allow() {
        // String Not Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucket";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","s3:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(403, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(200, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(200, listobjects3.first().intValue());
    }
    
    @Test
    public void test_listbucket_s3Prefix_StringNotEqual_deny() {
        // String Not Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucketdeny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","s3:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_listbucketallow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        System.out.println(policyString2);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(200, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(403, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(403, listobjects3.first().intValue());
    }
    
    @Test
    public void test_listbucket_s3Prefix_StringEqualIgnoreCase_allow() {
       // String Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucket";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","s3:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(200, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(403, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(200, listobjects3.first().intValue());
    }
    
    @Test
    public void test_listbucket_s3Prefix_StringEqualIgnoreCase_deny() {
       // String Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucketdeny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","s3:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_listbucketallow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        System.out.println(policyString2);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(403, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(200, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(403, listobjects3.first().intValue());
    }
    
    @Test
    public void test_listbucket_s3Prefix_StringNotEqualIgnoreCase_allow() {
        // String Not Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucket";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","s3:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(403, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(200, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(403, listobjects3.first().intValue());
        
    }
    
    @Test
    public void test_listbucket_s3Prefix_StringNotEqualIgnoreCase_deny() {
        // String Not Equal
        String httpOrHttps="https";
        String host="oos-cd.ctyunapi.cn";
        int jettyPort=8444;
        String signVersion="V4";
        String regionName="cd";
        String bucketName="yx-bucket-3";
        
        String policyName="test_listbucketdeny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","s3:prefix",Arrays.asList("${ctyun:username}/")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        
        String policyName2="test_listbucketallow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        System.out.println(policyString2);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name+"/",null,null,null,null);
        assertEquals(200, listobjects.first().intValue());
        
        Pair<Integer, String> listobjects2=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user2Name+"/",null,null,null,null);
        assertEquals(403, listobjects2.first().intValue());
        
        Pair<Integer, String> listobjects3=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, user1accessKey, user1secretKey, bucketName, user1Name.toUpperCase()+"/",null,null,null,null);
        assertEquals(200, listobjects3.first().intValue());
    }

    public static void AllowActionResourceUser_NoCreateDelete(String rootAK,String rootSK,String ak,String sk,String userName,List<Pair<String, String>> tags,String policyName, String policyString,String accountId) {

        IAMInterfaceTestUtils.GetUser(ak, sk, userName, 200);
        IAMInterfaceTestUtils.TagUser(ak, sk, userName, tags, 200);
        IAMInterfaceTestUtils.ListUserTags(ak, sk, userName, 200);
           
        List<String> tagKeys = new ArrayList<String>();
        for (int i = 0; i < tags.size(); i++) {
            tagKeys.add(tags.get(0).first());
        }
        
        IAMInterfaceTestUtils.UntagUser(ak, sk, userName, tagKeys, 200);
            
        String akId="";

        String xmlString =IAMInterfaceTestUtils.CreateAccessKey(ak, sk, userName, 200);
        akId=AssertCreateAccessKey(xmlString, userName, "Active");

        IAMInterfaceTestUtils.ListAccessKeys(ak, sk, userName, 200);
        IAMInterfaceTestUtils.UpdateAccessKey(ak, sk, akId, userName,"Inactive", 200);
        IAMInterfaceTestUtils.DeleteAccessKey(ak, sk, akId, userName,200);
        IAMInterfaceTestUtils.CreateLoginProfile(ak, sk, userName, "a12345678", 200);
        IAMInterfaceTestUtils.GetLoginProfile(ak, sk, userName, 200);
        IAMInterfaceTestUtils.UpdateLoginProfile(ak, sk, userName, "b987654321", 200);
        IAMInterfaceTestUtils.DeleteLoginProfile(ak, sk, userName, 200);
         
        String groupName="userResourceGroup";
        IAMInterfaceTestUtils.CreateGroup(rootAK, rootSK, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(rootAK, rootSK, groupName, userName, 200);
        IAMInterfaceTestUtils.ListGroupsForUser(ak, sk, userName, 200);
           
        String deviceName=userName;
        String xml=IAMInterfaceTestUtils.CreateVirtualMFADevice(rootAK, rootSK, deviceName, 200);
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(xml,"arn:ctyun:iam::"+accountId+":mfa/"+deviceName);
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
       
        IAMInterfaceTestUtils.EnableMFADevice(ak, sk, userName, accountId, deviceName, codesPair.first(), codesPair.second(), 200);
        IAMInterfaceTestUtils.CreatePolicy(rootAK, rootSK, policyName, policyString, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(ak, sk, accountId, userName, policyName, 200);   
        IAMInterfaceTestUtils.ListAttachedUserPolicies(ak, sk, userName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(ak, sk, accountId, userName, policyName, 200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(rootAK, rootSK, groupName, userName, 200);
        IAMInterfaceTestUtils.DeactivateMFADevice(rootAK, rootSK, userName, accountId, deviceName, 200);
        IAMInterfaceTestUtils.DeleteGroup(rootAK,rootSK,groupName,200);
        IAMInterfaceTestUtils.DeleteVirtualMFADevice(rootAK,rootSK,accountId,deviceName,200);   
    }
    
    public void AllowActionResourceBucket(String rootAk,String rootSk,String accessKey,String secretKey,String bucketName)  {
        String host="oos-cd.ctyunapi.cn";
        String httpOrHttps="https";
        int jettyPort=8444;
        String signVersion="V4";
        
        // 创建bucket  
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null, null, null, null, null);
        assertEquals(200, createbucket2.first().intValue());
        System.out.println(createbucket2.second());
//        
//        // 获取bucket的ACL信息
        Pair<Integer, String> getbucketacl=OOSAPITestUtils.Bucket_GetAcl(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(200, getbucketacl.first().intValue());
        System.out.println(getbucketacl.second());
        
        // 修改bucket acl属性
        HashMap<String, String> updateaclParams=new HashMap<String, String>();
        updateaclParams.put("x-amz-acl", "public-read-write");
        Pair<Integer, String> updatebucket=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, "Local", null, null, "NotAllowed", updateaclParams);
        assertEquals(200, updatebucket.first().intValue());
        System.out.println(updatebucket.second());
        
        // 获取bucket的索引位置和数据位置 
        Pair<Integer, String> getbucketlocation=OOSAPITestUtils.Bucket_GetLocation(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(200, getbucketlocation.first().intValue());
        System.out.println(getbucketlocation.second());
        
        // 创建，获取，删除bucketpolicy
        String policyString = "{" + "\"Version\": \"2012-10-17\","
                + "\"Id\": \"preventHotLinking\"," + "\"Statement\": [" + " {"
                + " \"Sid\": \"1\"," + "\"Effect\": \"Allow\","
                + "\"Principal\": {" + " \"AWS\": \"*\"" + "},"
                + "\"Action\": \"s3:ListBucket\","
                + "\"Resource\": \"arn:aws:s3:::" + bucketName + "\","
                + "}]}";
        Pair<Integer, String> putbucketpolicy=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, policyString, null);
        assertEquals(200, putbucketpolicy.first().intValue());
        System.out.println(putbucketpolicy.second());
        
        Pair<Integer, String> getbucketpolicy=OOSAPITestUtils.Bucket_GetPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(200, getbucketpolicy.first().intValue());
        System.out.println(getbucketpolicy.second());
        
        Pair<Integer, String> delbucketpolicy=OOSAPITestUtils.Bucket_DeletePolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(200, delbucketpolicy.first().intValue());
        System.out.println(delbucketpolicy.second());
        
        // 创建，获取，删除website
        Pair<Integer, String> putbucketwebsite=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(200, putbucketwebsite.first().intValue());
        System.out.println(putbucketwebsite.second());
        
        Pair<Integer, String> getbucketwebsite=OOSAPITestUtils.Bucket_GetWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(200, getbucketwebsite.first().intValue());
        System.out.println(getbucketwebsite.second());
        
        Pair<Integer, String> delbucketwebsite=OOSAPITestUtils.Bucket_DeleteWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(200, delbucketwebsite.first().intValue());
        System.out.println(delbucketwebsite.second());
        
        // 创建，获取logging
        Pair<Integer, String> putbucketlogging=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, bucketName,"logs/",null);
        assertEquals(200, putbucketlogging.first().intValue());
        System.out.println(putbucketlogging.second());
        
        Pair<Integer, String> getbucketlogging=OOSAPITestUtils.Bucket_GetLogging(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(200, getbucketlogging.first().intValue());
        System.out.println(getbucketlogging.second());
        
        // 创建，获取，删除lifecycle
        Pair<Integer, String> putbucketlifecle=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName,"logs","Enabled",30, null);
        assertEquals(200, putbucketlifecle.first().intValue());
        System.out.println(putbucketlifecle.second());
        
        Pair<Integer, String> getbucketlifecle=OOSAPITestUtils.Bucket_GetLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(200, getbucketlifecle.first().intValue());
        System.out.println(getbucketlifecle.second());
        
        Pair<Integer, String> delbucketlifecle=OOSAPITestUtils.Bucket_DeleteLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(204, delbucketlifecle.first().intValue());
        System.out.println(delbucketlifecle.second());
        
        // 创建，获取cdn加速
        Pair<Integer, String> putbucketaccelerate=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(200, putbucketaccelerate.first().intValue());
        System.out.println(putbucketaccelerate.second());
        
        Pair<Integer, String> getbucketaccelerate=OOSAPITestUtils.Bucket_GetAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(200, getbucketaccelerate.first().intValue());
        System.out.println(getbucketaccelerate.second());
        
        // 创建，获取，删除cors 
        Pair<Integer, String> putbucketcors=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(200, putbucketcors.first().intValue());
        System.out.println(putbucketcors.second());
        
        Pair<Integer, String> getbucketcors=OOSAPITestUtils.Bucket_GetCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(200, getbucketcors.first().intValue());
        System.out.println(getbucketcors.second());
        
        Pair<Integer, String> delbucketcors=OOSAPITestUtils.Bucket_DeleteCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(200, delbucketcors.first().intValue());
        System.out.println(delbucketcors.second());
        
        Pair<Integer, String> listMultipartUploads=OOSAPITestUtils.Bucket_ListMultipartUploads(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(200, listMultipartUploads.first().intValue());
        
        String objectName1="1.txt";
        String objectName2="2.txt";
        
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, objectName1, "first", null);
        assertEquals(200, putobject.first().intValue());
        
        Pair<Integer, String> putobject2=OOSAPITestUtils.Object_Put(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, objectName2,"second", null);
        assertEquals(200, putobject2.first().intValue());
        
        Pair<Integer, String> delobjects=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, Arrays.asList(objectName1,objectName2), null);
        assertEquals(200, delobjects.first().intValue());
        System.out.println(delobjects.second());
        
        // delete bucket
        Pair<Integer, String> delbucket=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(204, delbucket.first().intValue());
        System.out.println(delbucket.second());
    }
    
    public void DenyActionResourceBucket(String rootAk,String rootSk,String accessKey,String secretKey,String bucketName) {
        String host="oos-cd.ctyunapi.cn";
        String httpOrHttps="https";
        int jettyPort=8444;
        String signVersion="V4";
        
        // 创建bucket  
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, "Local", null, null, null, null);
        assertEquals(403, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, "Local", null, null, null, null);
        assertEquals(200, createbucket2.first().intValue());
        System.out.println(createbucket2.second());
//        
//        // 获取bucket的ACL信息
        Pair<Integer, String> getbucketacl=OOSAPITestUtils.Bucket_GetAcl(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketacl.first().intValue());
        System.out.println(getbucketacl.second());
        
        // 修改bucket acl属性
        HashMap<String, String> updateaclParams=new HashMap<String, String>();
        updateaclParams.put("x-amz-acl", "public-read-write");
        Pair<Integer, String> updatebucket=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, "Local", null, null, "NotAllowed", updateaclParams);
        assertEquals(403, updatebucket.first().intValue());
        System.out.println(updatebucket.second());
        
        // 获取bucket的索引位置和数据位置 
        Pair<Integer, String> getbucketlocation=OOSAPITestUtils.Bucket_GetLocation(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketlocation.first().intValue());
        System.out.println(getbucketlocation.second());
        
        // 创建，获取，删除bucketpolicy
        String policyString = "{" + "\"Version\": \"2012-10-17\","
                + "\"Id\": \"preventHotLinking\"," + "\"Statement\": [" + " {"
                + " \"Sid\": \"1\"," + "\"Effect\": \"Allow\","
                + "\"Principal\": {" + " \"AWS\": \"*\"" + "},"
                + "\"Action\": \"s3:ListBucket\","
                + "\"Resource\": \"arn:aws:s3:::" + bucketName + "\","
                + "}]}";
        Pair<Integer, String> putbucketpolicy=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, policyString, null);
        assertEquals(403, putbucketpolicy.first().intValue());
        System.out.println(putbucketpolicy.second());
        
        Pair<Integer, String> putbucketpolicy2=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, policyString, null);
        assertEquals(200, putbucketpolicy2.first().intValue());
        System.out.println(putbucketpolicy2.second());
        
        Pair<Integer, String> getbucketpolicy=OOSAPITestUtils.Bucket_GetPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketpolicy.first().intValue());
        System.out.println(getbucketpolicy.second());
        
        Pair<Integer, String> delbucketpolicy=OOSAPITestUtils.Bucket_DeletePolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, delbucketpolicy.first().intValue());
        System.out.println(delbucketpolicy.second());
        
        // 创建，获取，删除website
        Pair<Integer, String> putbucketwebsite=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, putbucketwebsite.first().intValue());
        System.out.println(putbucketwebsite.second());
        
        Pair<Integer, String> putbucketwebsite2=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, null);
        assertEquals(200, putbucketwebsite2.first().intValue());
        System.out.println(putbucketwebsite2.second());
        
        Pair<Integer, String> getbucketwebsite=OOSAPITestUtils.Bucket_GetWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketwebsite.first().intValue());
        System.out.println(getbucketwebsite.second());
        
        Pair<Integer, String> delbucketwebsite=OOSAPITestUtils.Bucket_DeleteWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, delbucketwebsite.first().intValue());
        System.out.println(delbucketwebsite.second());
        
        // 创建，获取logging
        Pair<Integer, String> putbucketlogging=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, bucketName,"logs/",null);
        assertEquals(403, putbucketlogging.first().intValue());
        System.out.println(putbucketlogging.second());
        
        Pair<Integer, String> putbucketlogging2=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, bucketName,"logs/",null);
        assertEquals(200, putbucketlogging2.first().intValue());
        System.out.println(putbucketlogging2.second());
        
        Pair<Integer, String> getbucketlogging=OOSAPITestUtils.Bucket_GetLogging(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketlogging.first().intValue());
        System.out.println(getbucketlogging.second());
        
        // 创建，获取，删除lifecycle
        Pair<Integer, String> putbucketlifecle=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName,"logs","Enabled",30, null);
        assertEquals(403, putbucketlifecle.first().intValue());
        System.out.println(putbucketlifecle.second());
        
        Pair<Integer, String> putbucketlifecle2=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName,"logs","Enabled",30, null);
        assertEquals(200, putbucketlifecle2.first().intValue());
        System.out.println(putbucketlifecle2.second());
        
        Pair<Integer, String> getbucketlifecle=OOSAPITestUtils.Bucket_GetLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketlifecle.first().intValue());
        System.out.println(getbucketlifecle.second());
        
        Pair<Integer, String> delbucketlifecle=OOSAPITestUtils.Bucket_DeleteLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, delbucketlifecle.first().intValue());
        System.out.println(delbucketlifecle.second());
        
        // 创建，获取cdn加速
        Pair<Integer, String> putbucketaccelerate=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(403, putbucketaccelerate.first().intValue());
        System.out.println(putbucketaccelerate.second());
        
        Pair<Integer, String> putbucketaccelerate2=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(200, putbucketaccelerate2.first().intValue());
        System.out.println(putbucketaccelerate2.second());
        
        Pair<Integer, String> getbucketaccelerate=OOSAPITestUtils.Bucket_GetAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketaccelerate.first().intValue());
        System.out.println(getbucketaccelerate.second());
        
        // 创建，获取，删除cors 
        Pair<Integer, String> putbucketcors=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, putbucketcors.first().intValue());
        System.out.println(putbucketcors.second());
        
        Pair<Integer, String> putbucketcors2=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, null);
        assertEquals(200, putbucketcors2.first().intValue());
        System.out.println(putbucketcors2.second());
        
        Pair<Integer, String> getbucketcors=OOSAPITestUtils.Bucket_GetCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, getbucketcors.first().intValue());
        System.out.println(getbucketcors.second());
        
        Pair<Integer, String> delbucketcors=OOSAPITestUtils.Bucket_DeleteCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, delbucketcors.first().intValue());
        System.out.println(delbucketcors.second());
        
        Pair<Integer, String> listMultipartUploads=OOSAPITestUtils.Bucket_ListMultipartUploads(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, listMultipartUploads.first().intValue());
        
        String objectName1="1.txt";
        String objectName2="2.txt";
        
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, objectName1, "first", null);
        assertEquals(200, putobject.first().intValue());
        
        Pair<Integer, String> putobject2=OOSAPITestUtils.Object_Put(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, objectName2, "second", null);
        assertEquals(200, putobject2.first().intValue());
        
        Pair<Integer, String> delobjects=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, Arrays.asList(objectName1,objectName2), null);
        assertEquals(403, delobjects.first().intValue());
        System.out.println(delobjects.second());
        
        Pair<Integer, String> delobjects2=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, Arrays.asList(objectName1,objectName2), null);
        assertEquals(200, delobjects2.first().intValue());
        System.out.println(delobjects2.second());
        
        // delete bucket
        Pair<Integer, String> delbucket=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, null);
        assertEquals(403, delbucket.first().intValue());
        System.out.println(delbucket.second());
        
        Pair<Integer, String> delbucket2=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, null);
        assertEquals(204, delbucket2.first().intValue());
        System.out.println(delbucket2.second());
    }
    
    public void AllowActionResourceObject(String rootAk,String rootSk,String  accessKey,String secretKey,String bucketName,String prefix){
        String host="oos-cd.ctyunapi.cn";
        String httpOrHttps="https";
        int jettyPort=8444;
        String signVersion="V4";
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, "Local", null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
         //put get head delete object
        String objectName="src.txt";
        if (prefix!=null) {
            objectName=prefix+objectName;
        }
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), "first", null);
        assertEquals(200, putobject.first().intValue());
        System.out.println(putobject.second());
        
        Pair<Integer, String> getobject=OOSAPITestUtils.Object_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), null);
        assertEquals(200, getobject.first().intValue());
        System.out.println(getobject.second());
        
        int headobject=OOSAPITestUtils.Object_Head(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), null);
        assertEquals(200, headobject);
        
        Pair<Integer, String> delobject=OOSAPITestUtils.Object_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), null);
        assertEquals(204, delobject.first().intValue());
        System.out.println(delobject.second());
        
        // post object
        Pair<Integer, String> postobject=OOSAPITestUtils.Object_Post(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, objectName, "post.txt", null);
        assertEquals(204, postobject.first().intValue());
        System.out.println(postobject.second());
        
        // copy object
        String objectName2="desc.txt";
        if (prefix!=null) {
            objectName2=prefix+objectName2;
        }
        Pair<Integer, String> copyobject=OOSAPITestUtils.Object_Copy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), V4SignClient.urlEncode(objectName2, true), null);
        assertEquals(200, copyobject.first().intValue());
        System.out.println(copyobject.second());
        
        // bucket中的object信息
//        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName,null);
//        assertEquals(403, listobjects.first().intValue());
//        System.out.println(listobjects.second());
//        
//        Pair<Integer, String> listobjects1=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, prefix,null,null,null,null);
//        assertEquals(200, listobjects1.first().intValue());
//        System.out.println(listobjects1.second());
        
        // 分段上传，1.init 2.uploadpart,3.copy part,4.List Multipart Uploads,5.list part 6.Complete Multipart Upload,7.Abort Multipart Upload
        String objectName3="muli.txt";
        if (prefix!=null) {
            objectName3=prefix+objectName3;
        }
        Pair<Integer, String> initmuli=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), null);
        assertEquals(200, initmuli.first().intValue());
        String uploadId=OOSAPITestUtils.getMultipartUploadId(initmuli.second());
        
        Pair<Integer, String> uploadpart=OOSAPITestUtils.Object_UploadPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, 1, "123", null);
        assertEquals(200, uploadpart.first().intValue());
        String etag1=uploadpart.second();
        Pair<Integer, String> copypart=OOSAPITestUtils.Object_CopyPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, 2, V4SignClient.urlEncode(objectName, true), null);
        assertEquals(200, copypart.first().intValue());
        String etag2=OOSAPITestUtils.getCopyPartEtag(copypart.second());
       
        Pair<Integer, String> listpart=OOSAPITestUtils.Object_ListPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, null);
        assertEquals(200, listpart.first().intValue());
        System.out.println(listpart.second());
        
        Map<String, String> partEtagMap = new HashMap<String, String>();
        partEtagMap.put("1", etag1);
        partEtagMap.put("2", etag2);

        Pair<Integer, String> completemultipart=OOSAPITestUtils.Object_CompleteMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName,V4SignClient.urlEncode(objectName3, true), uploadId, partEtagMap, null);
        assertEquals(200, completemultipart.first().intValue());
        System.out.println(completemultipart.second());
        
        String objectName4="muli2.txt";
        if (prefix!=null) {
            objectName4=prefix+objectName4;
        }
        Pair<Integer, String> initmuli2=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName4, true), null);
        assertEquals(200, initmuli2.first().intValue());
        String uploadId2=OOSAPITestUtils.getMultipartUploadId(initmuli2.second());
        
        Pair<Integer, String> uploadpart2=OOSAPITestUtils.Object_UploadPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName4, true), uploadId2, 1, "123", null);
        assertEquals(200, uploadpart2.first().intValue());
        String etag3=uploadpart2.second();
        Pair<Integer, String> copypart2=OOSAPITestUtils.Object_CopyPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName4, true), uploadId2, 2, V4SignClient.urlEncode(objectName, true), null);
        assertEquals(200, copypart2.first().intValue());
        String etag4=OOSAPITestUtils.getCopyPartEtag(copypart2.second());

        Pair<Integer, String> aboutmultipart=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName4, true), uploadId2, null);
        assertEquals(204, aboutmultipart.first().intValue());
        System.out.println(aboutmultipart.second());
        
        Pair<Integer, String> delobjects2=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, Arrays.asList(objectName,objectName2,objectName3,objectName4), null);
        assertEquals(200, delobjects2.first().intValue());
        System.out.println(delobjects2.second());
        
        // delete bucket
        Pair<Integer, String> delbucket2=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, null);
        assertEquals(204, delbucket2.first().intValue());
        System.out.println(delbucket2.second());
    }
    
    public void DenyActionResourceObject(String rootAk,String rootSk,String  accessKey,String secretKey,String bucketName,String prefix){
        String host="oos-cd.ctyunapi.cn";
        String httpOrHttps="https";
        int jettyPort=8444;
        String signVersion="V4";
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, "Local", null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
         //put get head delete object
        String objectName="src.txt";
        if (prefix!=null) {
            objectName=prefix+objectName;
        }
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), "first", null);
        assertEquals(403, putobject.first().intValue());
        System.out.println(putobject.second());
        
        Pair<Integer, String> putobject1=OOSAPITestUtils.Object_Put(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, V4SignClient.urlEncode(objectName, true), "first", null);
        assertEquals(200, putobject1.first().intValue());
        System.out.println(putobject1.second());
        
        Pair<Integer, String> getobject=OOSAPITestUtils.Object_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), null);
        assertEquals(403, getobject.first().intValue());
        System.out.println(getobject.second());
        
        int headobject=OOSAPITestUtils.Object_Head(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), null);
        assertEquals(403, headobject);
        
        Pair<Integer, String> delobject=OOSAPITestUtils.Object_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), null);
        assertEquals(403, delobject.first().intValue());
        System.out.println(delobject.second());
        
        
        // post object
        Pair<Integer, String> postobject=OOSAPITestUtils.Object_Post(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, objectName,"post.txt", null);
        assertEquals(403, postobject.first().intValue());
        System.out.println(postobject.second());
        
        // copy object
        String objectName2="desc.txt";
        if (prefix!=null) {
            objectName2=prefix+objectName2;
        }
        Pair<Integer, String> copyobject=OOSAPITestUtils.Object_Copy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName, true), V4SignClient.urlEncode(objectName2, true), null);
        assertEquals(403, copyobject.first().intValue());
        System.out.println(copyobject.second());
        
        // bucket中的object信息
//        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName,null);
//        assertEquals(403, listobjects.first().intValue());
//        System.out.println(listobjects.second());
//        
//        Pair<Integer, String> listobjects1=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, prefix,null,null,null,null);
//        assertEquals(200, listobjects1.first().intValue());
//        System.out.println(listobjects1.second());
        
        // 分段上传，1.init 2.uploadpart,3.copy part,4.List Multipart Uploads,5.list part 6.Complete Multipart Upload,7.Abort Multipart Upload
        String objectName3="muli.txt";
        if (prefix!=null) {
            objectName3=prefix+objectName3;
        }
        Pair<Integer, String> initmuli=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), null);
        assertEquals(403, initmuli.first().intValue());
 
        Pair<Integer, String> initmuliroot=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, V4SignClient.urlEncode(objectName3, true), null);
        assertEquals(200, initmuliroot.first().intValue());
        String uploadId=OOSAPITestUtils.getMultipartUploadId(initmuliroot.second());
        
        Pair<Integer, String> uploadpart=OOSAPITestUtils.Object_UploadPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, 1, "123", null);
        assertEquals(403, uploadpart.first().intValue());
        Pair<Integer, String> copypart=OOSAPITestUtils.Object_CopyPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, 2, V4SignClient.urlEncode(objectName,true), null);
        assertEquals(403, copypart.first().intValue());
        
        Pair<Integer, String> uploadpartroot=OOSAPITestUtils.Object_UploadPart(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, 1, "123", null);
        assertEquals(200, uploadpartroot.first().intValue());
        String etag1=uploadpartroot.second();
        Pair<Integer, String> copypartroot=OOSAPITestUtils.Object_CopyPart(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, 2, V4SignClient.urlEncode(objectName,true), null);
        assertEquals(200, copypartroot.first().intValue());
        String etag2=OOSAPITestUtils.getCopyPartEtag(copypartroot.second());
        
        Pair<Integer, String> listpart=OOSAPITestUtils.Object_ListPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, null);
        assertEquals(403, listpart.first().intValue());
        System.out.println(listpart.second());
        
        Map<String, String> partEtagMap = new HashMap<String, String>();
        partEtagMap.put("1", etag1);
        partEtagMap.put("2", etag2);

        Pair<Integer, String> completemultipart=OOSAPITestUtils.Object_CompleteMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName,V4SignClient.urlEncode(objectName3, true), uploadId, partEtagMap, null);
        assertEquals(403, completemultipart.first().intValue());
        System.out.println(completemultipart.second());
        
        Pair<Integer, String> aboutmultipart=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, null);
        assertEquals(403, aboutmultipart.first().intValue());
        System.out.println(aboutmultipart.second());
        
        Pair<Integer, String> aboutmultipartroot=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, V4SignClient.urlEncode(objectName3, true), uploadId, null);
        assertEquals(204, aboutmultipartroot.first().intValue());
        System.out.println(aboutmultipartroot.second());
        
        Pair<Integer, String> delobjects2=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, Arrays.asList(objectName, objectName3), null);
        assertEquals(200, delobjects2.first().intValue());
        System.out.println(delobjects2.second());
        
        // delete bucket
        Pair<Integer, String> delbucket2=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, rootAk, rootSk, bucketName, null);
        assertEquals(204, delbucket2.first().intValue());
        System.out.println(delbucket2.second());
    }
    
    
    public void AllowActionResourceTrail(String accessKey,String secretKey,String trailName) {
 
        Pair<Integer, String> createtrail=CloudTrailAPITestUtils.CreateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, cloudtrailBucket, true, null);
        assertEquals(200, createtrail.first().intValue());
        System.out.println(createtrail.second());

        Pair<Integer, String> updateTrail=CloudTrailAPITestUtils.UpdateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, cloudtrailBucket, null, true, null);
        assertEquals(200, updateTrail.first().intValue());
        System.out.println(updateTrail.second());
        
        Pair<Integer, String> putEventSelectors=CloudTrailAPITestUtils.PutEventSelectors(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, "All", true, null);
        assertEquals(200, putEventSelectors.first().intValue());
        System.out.println(putEventSelectors.second());
        
        Pair<Integer, String> getEventSelectors=CloudTrailAPITestUtils.GetEventSelectors(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, null);
        assertEquals(200, getEventSelectors.first().intValue());
        System.out.println(getEventSelectors.second());

        Pair<Integer, String> startLogging=CloudTrailAPITestUtils.StartLogging(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, null);
        assertEquals(200, startLogging.first().intValue());
        System.out.println(startLogging.second());
        
        Pair<Integer, String> getTrailStatus=CloudTrailAPITestUtils.GetTrailStatus(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, null);
        assertEquals(200, getTrailStatus.first().intValue());
        System.out.println(getTrailStatus.second());
        
        Pair<Integer, String> stopLogging=CloudTrailAPITestUtils.StopLogging(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, null);
        assertEquals(200, stopLogging.first().intValue());
        System.out.println(stopLogging.second());
 
        Pair<Integer, String> deleteTrail=CloudTrailAPITestUtils.DeleteTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, null);
        assertEquals(200, deleteTrail.first().intValue());
        System.out.println(deleteTrail.second());
    }
    
    public void DenyActionResourceTrail(String rootAk,String rootSk,String accessKey,String secretKey,String trailName) {
        Pair<Integer, String> createtrail=CloudTrailAPITestUtils.CreateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, cloudtrailBucket, true, null);
        assertEquals(403, createtrail.first().intValue());
        System.out.println(createtrail.second());
        
        Pair<Integer, String> createtrail2=CloudTrailAPITestUtils.CreateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, rootAk, rootSk, trailName, cloudtrailBucket, true, null);
        assertEquals(200, createtrail2.first().intValue());
        System.out.println(createtrail2.second());

        Pair<Integer, String> updateTrail=CloudTrailAPITestUtils.UpdateTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, cloudtrailBucket, null, true, null);
        assertEquals(403, updateTrail.first().intValue());
        System.out.println(updateTrail.second());
        
        Pair<Integer, String> putEventSelectors=CloudTrailAPITestUtils.PutEventSelectors(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, "All", true, null);
        assertEquals(403, putEventSelectors.first().intValue());
        System.out.println(putEventSelectors.second());
        
        Pair<Integer, String> getEventSelectors=CloudTrailAPITestUtils.GetEventSelectors(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, null);
        assertEquals(403, getEventSelectors.first().intValue());
        System.out.println(getEventSelectors.second());

        Pair<Integer, String> startLogging=CloudTrailAPITestUtils.StartLogging(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, null);
        assertEquals(403, startLogging.first().intValue());
        System.out.println(startLogging.second());
        
        Pair<Integer, String> getTrailStatus=CloudTrailAPITestUtils.GetTrailStatus(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, null);
        assertEquals(403, getTrailStatus.first().intValue());
        System.out.println(getTrailStatus.second());
        
        Pair<Integer, String> stopLogging=CloudTrailAPITestUtils.StopLogging(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, null);
        assertEquals(403, stopLogging.first().intValue());
        System.out.println(stopLogging.second());
 
        Pair<Integer, String> deleteTrail=CloudTrailAPITestUtils.DeleteTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, accessKey, secretKey, trailName, true, null);
        assertEquals(403, deleteTrail.first().intValue());
        System.out.println(deleteTrail.second());
        
        Pair<Integer, String> deleteTrail2=CloudTrailAPITestUtils.DeleteTrail(OOS_CLOUDTRAIL_DOMAIN, regionName, rootAk, rootSk, trailName, true, null);
        assertEquals(200, deleteTrail2.first().intValue());
        System.out.println(deleteTrail2.second());
    }
    

    public String getCreateAccessKey(String xml) {
        try {
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = doc.getRootElement();
            
            Element createAKResultElement=root.getChild("CreateAccessKeyResult");
            Element AkElement=createAKResultElement.getChild("AccessKey");
            String ak=AkElement.getChild("AccessKeyId").getValue();
            System.out.println(ak);
            System.out.println(AkElement.getChild("SecretAccessKey").getValue());
            System.out.println(AkElement.getChild("CreateDate").getValue());
            
            return ak;
            } catch (Exception e) {
                // TODO: handle exception
            }
            return null;
        }
    
    public static String AssertCreateAccessKey(String xml,String username,String status) {
        try {
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = doc.getRootElement();
            
            Element createAKResultElement=root.getChild("CreateAccessKeyResult");
            Element AkElement=createAKResultElement.getChild("AccessKey");
            assertEquals(username, AkElement.getChild("UserName").getValue());
            assertEquals(status, AkElement.getChild("Status").getValue());
            String ak=AkElement.getChild("AccessKeyId").getValue();
            System.out.println(ak);
            System.out.println(AkElement.getChild("SecretAccessKey").getValue());
            System.out.println(AkElement.getChild("CreateDate").getValue());
            
            return ak;
        } catch (Exception e) {
            e.getStackTrace();
        }
        return null;
    }
    
    public static Pair<String, String> AssertcreateVirtualMFADevice(String xml,String serialNumber) {
        try {
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = doc.getRootElement();
            
            Element resultElement=root.getChild("CreateVirtualMFADeviceResult");
            Element virtualMFADevice=resultElement.getChild("VirtualMFADevice");
            String SerialNumber=virtualMFADevice.getChild("SerialNumber").getValue();
            String Base32StringSeed=virtualMFADevice.getChild("Base32StringSeed").getValue();
            String QRCodePNG=virtualMFADevice.getChild("QRCodePNG").getValue();
            System.out.println("QRCodePNG="+QRCodePNG);
            assertEquals(serialNumber, SerialNumber);
            Pair<String, String> pair = new Pair<String, String>();
            pair.first(SerialNumber);
            pair.second(Base32StringSeed);
            return pair;
        } catch (Exception e) {
            e.getStackTrace();
        }
        
        return null;
    }
    
    public static Pair<String, String> CreateIdentifyingCode(String secret) {
        Pair<String, String> codePair = new Pair<String, String>();
        int WINDOW_SIZE = 3;
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);
        long t = System.currentTimeMillis() / 1000L / 30L;
        for (int i = -WINDOW_SIZE; i <= WINDOW_SIZE; ++i) {
            long hash1 = generateCode(decodedKey, t + i);
            long hash2 = generateCode(decodedKey, t + i + 1);
            codePair.first(String.valueOf(hash1));
            codePair.second(String.valueOf(hash2));
        }
        return codePair;
    }
    
     private static int generateCode(byte[] key, long t)  {
            byte[] data = new byte[8];
            long value = t;
            for (int i = 8; i-- > 0; value >>>= 8) {
                data[i] = (byte) value;
            }
            SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
            Mac mac;
            try {
                mac = Mac.getInstance("HmacSHA1");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            try {
                mac.init(signKey);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }
            byte[] hash = mac.doFinal(data);
            int offset = hash[20 - 1] & 0xF;
            // We're using a long because Java hasn't got unsigned int.
            long truncatedHash = 0;
            for (int i = 0; i < 4; ++i) {
                truncatedHash <<= 8;
                // We are dealing with signed bytes:
                // we just keep the first byte.
                truncatedHash |= (hash[offset + i] & 0xFF);
            }
            truncatedHash &= 0x7FFFFFFF;
            truncatedHash %= 1000000;
            return (int) truncatedHash;
        }
     
     public static JSONObject ParseErrorToJson(String xml) {
         
         try {
             StringReader sr = new StringReader(xml);
             InputSource is = new InputSource(sr);
             Document doc = (new SAXBuilder()).build(is);
             Element root = doc.getRootElement();
             
             String code=root.getChild("Code").getValue();
             String message=root.getChild("Message").getValue();
             String resource=root.getChild("Resource").getValue();
             String requestId=root.getChild("RequestId").getValue();
             
             JSONObject jObject= new JSONObject();
             jObject.put("Code", code);
             jObject.put("Message", message);
             jObject.put("Resource", resource);
             jObject.put("RequestId", requestId);
             
             return jObject;
             
         } catch (Exception e) {
             // TODO Auto-generated catch block
             e.printStackTrace();
         }
         return null; 
     }
}
