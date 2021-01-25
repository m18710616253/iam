package cn.ctyun.oos.iam.test.InternalAPI;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.io.IOUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.apache.xpath.operations.Bool;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.json.JSONArray;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xml.sax.InputSource;

import com.amazonaws.util.json.JSONException;
import com.amazonaws.util.json.JSONObject;

import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.hbase.HBaseRole;
import cn.ctyun.oos.hbase.HBaseUserToRole;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
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
import cn.ctyun.oos.utils.api.CloudTrailAPITestUtils;
import cn.ctyun.oos.utils.api.IAMAPITestUtils;
import cn.ctyun.oos.utils.api.ManagementAPITestUtils;
import cn.ctyun.oos.utils.api.OOSAPITestUtils;
import common.time.TimeUtils;
import common.tuple.Pair;

public class SystemPolicyTest {
    public static final String internalDomain="http://oos-cd-iam.ctyunapi.cn:9097/internal/";
    public static String ownerName = "root_user1@test.com";
    public static final String accessKey="userak1";
    public static final String secretKey="usersk1";
    public static final String accountId="3fdmxmc3pqvmp";
    public static String user1Name="user1";
    public static String user2Name="user2";
    public static final String user1accessKey="abcdefghijklmnop";
    public static final String user1secretKey="cccccccccccccccc";
    public static final String user2accessKey="bbbbbbbbbbbbbbbb";
    public static final String user2secretKey="ddddddddddddddddd";
    
    public static String ownerName2 = "root_user2@test.com";
    public static final String accessKey2="userak2";
    public static final String secretKey2="usersk2";

    public static MetaClient metaClient = MetaClient.getGlobalClient();
    public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static OwnerMeta owner2 = new OwnerMeta(ownerName2);
    
    public static final String cloudtrailBucket="cloudtrail-bucket";
    
    
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        CreateUser();
        initTag();
//        addUsrToRole(Arrays.asList("yxregion1"));
        Pair<Integer, String> putbucket=OOSAPITestUtils.Bucket_Put("http", "oos-cd.ctyunapi.cn", 80, "V2", "cd", accessKey, secretKey, cloudtrailBucket, "Local", null, null, null, null);
        assertEquals(200, putbucket.first().intValue());
    }

    @Before
    public void setUp() throws Exception {
    }

    
    public static void CreateUser() throws Exception {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);
        owner.email=ownerName;
        owner.setPwd("123456");
        owner.maxAKNum=10;
        owner.displayName="测试根用户1";
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
        user1.userId="Test1Abc";
        user1.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user1);
            assertTrue(success);
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        AkSkMeta aksk1 = new AkSkMeta(owner.getId());
        aksk1.isRoot = 0;
        aksk1.userId = user1.userId;
        aksk1.userName = UserName1;
        aksk1.accessKey=user1accessKey;
        aksk1.setSecretKey(user1secretKey);
        metaClient.akskInsert(aksk1);
        user1.accessKeys = new ArrayList<>();
        user1.userName=UserName1;
        user1.accessKeys.add(aksk1.accessKey);
        HBaseUtils.put(user1);
        
        String userName2=user2Name; 
        User user2=new User();
        user2.accountId=accountId;
        user2.userName=userName2;
        user2.userId="Test2";
        user2.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user2);
            assertTrue(success);
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        AkSkMeta aksk3 = new AkSkMeta(owner.getId());
        aksk3.isRoot = 0;
        aksk3.userId = user2.userId;
        aksk3.userName = userName2;
        aksk3.accessKey=user2accessKey;
        aksk3.setSecretKey(user2secretKey);
        metaClient.akskInsert(aksk3);
        user2.accessKeys = new ArrayList<>();
        user2.userName=userName2;
        user2.accessKeys.add(aksk3.accessKey);
        HBaseUtils.put(user2);
        
        owner2.email=ownerName2;
        owner2.setPwd("123456");
        owner2.maxAKNum=10;
        owner2.displayName="测试根用户2";
        owner2.bucketCeilingNum=10;
        metaClient.ownerInsertForTest(owner2);
        AkSkMeta aksk2=new AkSkMeta(owner2.getId());
        aksk2.accessKey=accessKey2;
        aksk2.setSecretKey(secretKey2);
        aksk2.isPrimary=1;
        metaClient.akskInsert(aksk2);
    }
    
    @Test
    public void test() {
        
    }
    
    @Test
    /*
     * 正常创建一个系统策略
     */
    public void test_OOSPolicy_CreatePolicy() throws Exception{
        
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
    }
    
    @Test
    /*
     * 系统策略中存在同名策略
     */
    public void test_OOSPolicy_CreatePolicy_Exist() throws Exception{
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        
        Pair<Integer, String> result2=internalRequest(url, body);
        assertEquals(409, result2.first().intValue());
        JSONObject jo=new JSONObject(result2.second());
        assertEquals(409, jo.getInt("status"));
        assertEquals("EntityAlreadyExists", jo.getString("code"));
        assertEquals("OOS policy with name "+policyName+" already exists.", jo.getString("message"));
        assertEquals("oosPolicyAlreadyExists", jo.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    
    @Test
    /*
     * 系统策略中不存在同名策略，但自定义策略中存在
     */
    public void test_OOSPolicy_CreatePolicy_Exist2() throws Exception{
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);

        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        
        // 自定义策略
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyDocument,200);
        
        Thread.sleep(3000);
        // 系统策略
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
    }
    
    
    @Test
    /*
     * 请求参数PolicyName不携带
     */
    public void test_OOSPolicy_CreatePolicy_noParamPolicyName() throws Exception{
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(null, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.getString("code"));
        assertEquals("PolicyName must not be empty.", jo.getString("message"));
        assertEquals("policyNameEmpty", jo.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));

    }
    
    @Test
    public void test_OOSPolicy_CreatePolicy_noParamPolicyDocument() throws Exception{
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, null, description);
        Pair<Integer, String> result=internalRequest(url, body);
        
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.getString("code"));
        assertEquals("PolicyDocument must not be empty.", jo.getString("message"));
        assertEquals("policyDocumentEmpty", jo.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    public void test_OOSPolicy_CreatePolicy_noParamDescription() throws Exception{
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, null);
        Pair<Integer, String> result=internalRequest(url, body);
        
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.getString("code"));
        assertEquals("Description must not be empty.", jo.getString("message"));
        assertEquals("policyDescriptionEmpty", jo.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    /*
     * 请求参数PolicyName为""
     */
    public void test_OOSPolicy_CreatePolicy_PolicyNameEmtpy() throws Exception{
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.getString("code"));
        assertEquals("PolicyName must not be empty.", jo.getString("message"));
        assertEquals("policyNameEmpty", jo.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    public void test_OOSPolicy_CreatePolicy_PolicyDocumentEmpty() throws Exception{
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument="";
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.getString("code"));
        assertEquals("PolicyDocument must not be empty.", jo.getString("message"));
        assertEquals("policyDocumentEmpty", jo.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    public void test_OOSPolicy_CreatePolicy_DescriptionEmpty() throws Exception{
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.getString("code"));
        assertEquals("Description must not be empty.", jo.getString("message"));
        assertEquals("policyDescriptionEmpty", jo.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    /*
     * 这里跟自定义的不同，除了空，所有都支持。
     */
    public void test_OOSPolicy_CreatePolicy_PolicyNameError() throws Exception{
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="my test ";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        
        assertEquals(200, result.first().intValue());
//        JSONObject jo=new JSONObject(result.second());
//        assertEquals(400, jo.getInt("status"));
//        assertEquals("InvalidArgument", jo.getString("code"));
//        assertEquals("PolicyName must not be empty.", jo.getString("message"));
//        assertEquals("policyNameEmpty", jo.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    public void test_OOSPolicy_CreatePolicy_PolicyDocumentError()throws Exception {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="123";
        String policyDocument="{}";
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("MalformedPolicyDocument", jo.getString("code"));
        assertEquals("The policy must contain a valid version string.", jo.getString("message"));
        assertEquals("invalidPolicyVersion", jo.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    /*
     * 创建policy名不同，policyDocument一样的系统策略
     */
    public void test_OOSPolicy_CreatePolicy_samePolicyDocument() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        String policyName2="oospolicy2";
        String body2=createSystemPolicyParam(policyName2, policyDocument, description);
        Pair<Integer, String> result2=internalRequest(url, body2);
        JSONObject jo2=new JSONObject(result2.second());
        assertNotNull(jo2.getString("policyId"));
        assertEquals("OOS", jo2.getString("accountId"));
        assertEquals(policyName2, jo2.getString("policyName"));
        assertEquals("OOS", jo2.getString("scope"));
        assertEquals(policyDocument, jo2.getString("document"));
        assertEquals(description, jo2.getString("description"));
        assertNotNull(jo2.getInt("createDate"));
        assertNotNull(jo2.getInt("updateDate"));
        assertEquals(jo2.getInt("createDate"), jo2.getInt("updateDate"));
        assertEquals("true", jo2.getString("isAttachable"));
        
    }
    
    
    @Test
    public void test_OOSPolicy_UpdatePolicy() throws Exception{
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        String url2=internalDomain+"updatePolicy";
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description2="更新系统策略";
        String body2=createSystemPolicyParam(policyName, policyDocument2, description2);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(200, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertNotNull(jo2.getString("policyId"));
        assertEquals("OOS", jo2.getString("accountId"));
        assertEquals(policyName, jo2.getString("policyName"));
        assertEquals("OOS", jo2.getString("scope"));
        assertEquals(policyDocument2, jo2.getString("document"));
        assertEquals(description2, jo2.getString("description"));
        assertNotNull(jo2.getInt("createDate"));
        assertNotNull(jo2.getInt("updateDate"));
        assertNotEquals(jo2.getInt("createDate"), jo2.getInt("updateDate"));
        assertEquals("true", jo2.getString("isAttachable"));
        assertFalse(result2.second().contains("attachedTotal"));
        
    }
    
    
    @Test
    public void test_OOSPolicy_UpdatePolicy_Attached() throws Exception{
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        
        String url2=internalDomain+"updatePolicy";
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description2="更新系统策略";
        String body2=createSystemPolicyParam(policyName, policyDocument2, description2);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(200, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertNotNull(jo2.getString("policyId"));
        assertEquals("OOS", jo2.getString("accountId"));
        assertEquals(policyName, jo2.getString("policyName"));
        assertEquals("OOS", jo2.getString("scope"));
        assertEquals(policyDocument2, jo2.getString("document"));
        assertEquals(description2, jo2.getString("description"));
        assertNotNull(jo2.getInt("createDate"));
        assertNotNull(jo2.getInt("updateDate"));
        assertNotEquals(jo2.getInt("createDate"), jo2.getInt("updateDate"));
        assertEquals("true", jo2.getString("isAttachable"));
        assertEquals(1, jo2.getInt("attachedTotal"));
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
    
    }
    
    @Test
    public void test_OOSPolicy_UpdatePolicy_noParamPolicyName() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        String url2=internalDomain+"updatePolicy";
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description2="更新系统策略";
        String body2=createSystemPolicyParam(null, policyDocument2, description2);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(400, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(400, jo2.getInt("status"));
        assertEquals("InvalidArgument", jo2.getString("code"));
        assertEquals("PolicyName must not be empty.", jo2.getString("message"));
        assertEquals("policyNameEmpty", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    public void test_OOSPolicy_UpdatePolicy_noParamPolicyDocument() throws JSONException {
        
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        String url2=internalDomain+"updatePolicy";
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description2="更新系统策略";
        String body2=createSystemPolicyParam(policyName, null, description2);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(400, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(400, jo2.getInt("status"));
        assertEquals("InvalidArgument", jo2.getString("code"));
        assertEquals("PolicyDocument must not be empty.", jo2.getString("message"));
        assertEquals("policyDocumentEmpty", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    public void test_OOSPolicy_UpdatePolicy_noParamDescription() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        String url2=internalDomain+"updatePolicy";
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description2="更新系统策略";
        String body2=createSystemPolicyParam(policyName, policyDocument2, null);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(400, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(400, jo2.getInt("status"));
        assertEquals("InvalidArgument", jo2.getString("code"));
        assertEquals("Description must not be empty.", jo2.getString("message"));
        assertEquals("policyDescriptionEmpty", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    public void test_OOSPolicy_UpdatePolicy_PolicyNameEmtpy() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        String url2=internalDomain+"updatePolicy";
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description2="更新系统策略";
        String body2=createSystemPolicyParam("", policyDocument2, description2);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(400, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(400, jo2.getInt("status"));
        assertEquals("InvalidArgument", jo2.getString("code"));
        assertEquals("PolicyName must not be empty.", jo2.getString("message"));
        assertEquals("policyNameEmpty", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    public void test_OOSPolicy_UpdatePolicy_PolicyDocumentEmpty() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        String url2=internalDomain+"updatePolicy";
        String policyDocument2="";
        String description2="更新系统策略";
        String body2=createSystemPolicyParam(policyName, policyDocument2, description2);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(400, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(400, jo2.getInt("status"));
        assertEquals("InvalidArgument", jo2.getString("code"));
        assertEquals("PolicyDocument must not be empty.", jo2.getString("message"));
        assertEquals("policyDocumentEmpty", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    public void test_OOSPolicy_UpdatePolicy_DescriptionEmpty() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        String url2=internalDomain+"updatePolicy";
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description2="更新系统策略";
        String body2=createSystemPolicyParam(policyName, policyDocument2, "");
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(400, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(400, jo2.getInt("status"));
        assertEquals("InvalidArgument", jo2.getString("code"));
        assertEquals("Description must not be empty.", jo2.getString("message"));
        assertEquals("policyDescriptionEmpty", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    
    @Test
    public void test_OOSPolicy_UpdatePolicy_PolicyDocumentError() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        String url2=internalDomain+"updatePolicy";
        String policyDocument2="{\"Effect\":\"allow\"}";
        String description2="更新系统策略";
        String body2=createSystemPolicyParam(policyName, policyDocument2, description2);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(400, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(400, jo2.getInt("status"));
        assertEquals("MalformedPolicyDocument", jo2.getString("code"));
        assertEquals("The policy must contain a valid version string.", jo2.getString("message"));
        assertEquals("invalidPolicyVersion", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    /*
     * 系统策略不存在
     */
    public void test_OOSPolicy_UpdatePolicy_PolicyNotExist() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);

        String policyName="oospolicy1";

        String url2=internalDomain+"updatePolicy";
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description2="更新系统策略";
        String body2=createSystemPolicyParam(policyName, policyDocument2, description2);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(404, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(404, jo2.getInt("status"));
        assertEquals("NoSuchEntity", jo2.getString("code"));
        assertEquals("The OOS policy with name "+policyName+" cannot be found.", jo2.getString("message"));
        assertEquals("oosPolicyNotExists", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    /*
     * 系统策略不存在,但自定义策略存在
     */
    public void test_OOSPolicy_UpdatePolicy_PolicyNotExist2() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);

        String policyName="oospolicy1";
        String url2=internalDomain+"updatePolicy";
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description2="更新系统策略";
        
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyDocument2, 200);
        
        String body2=createSystemPolicyParam(policyName, policyDocument2, description2);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(404, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(404, jo2.getInt("status"));
        assertEquals("NoSuchEntity", jo2.getString("code"));
        assertEquals("The OOS policy with name "+policyName+" cannot be found.", jo2.getString("message"));
        assertEquals("oosPolicyNotExists", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
    }
    
    @Test
    public void test_OOSPolicy_DeletePolicy() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        String url2=internalDomain+"deletePolicy";
        String body2=createSystemPolicyParam(policyName, null, null);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(200, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(policyName, jo2.getString("policyName"));
    }
    
    @Test
    public void test_OOSPolicy_DeletePolicy_NoParamPolicyName() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        
        String url2=internalDomain+"deletePolicy";
        String body2=createSystemPolicyParam(null, null, null);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(400, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(400, jo2.getInt("status"));
        assertEquals("InvalidArgument", jo2.getString("code"));
        assertEquals("PolicyName must not be empty.", jo2.getString("message"));
        assertEquals("policyNameEmpty", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));

        
    }
    
    @Test
    public void test_OOSPolicy_DeletePolicy_PolicyNameEmpty() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";

        String url2=internalDomain+"deletePolicy";
        String body2=createSystemPolicyParam("", null, null);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(400, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(400, jo2.getInt("status"));
        assertEquals("InvalidArgument", jo2.getString("code"));
        assertEquals("PolicyName must not be empty.", jo2.getString("message"));
        assertEquals("policyNameEmpty", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));

    }
    
    @Test
    /*
     * 系统策略不存在
     */
    public void test_OOSPolicy_DeletePolicy_PolicyNotExist() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";

        String url2=internalDomain+"deletePolicy";
        String body2=createSystemPolicyParam(policyName, null, null);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(404, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(404, jo2.getInt("status"));
        assertEquals("NoSuchEntity", jo2.getString("code"));
        assertEquals("The OOS policy with name "+policyName+" cannot be found.", jo2.getString("message"));
        assertEquals("oosPolicyNotExists", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));
  
    }
    
    @Test
    /*
     * 系统策略不存在，自定义策略存在
     */
    public void test_OOSPolicy_DeletePolicy_PolicyNotExist2() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyDocument, 200);

        String url2=internalDomain+"deletePolicy";
        String body2=createSystemPolicyParam(policyName, null, null);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(404, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(404, jo2.getInt("status"));
        assertEquals("NoSuchEntity", jo2.getString("code"));
        assertEquals("The OOS policy with name "+policyName+" cannot be found.", jo2.getString("message"));
        assertEquals("oosPolicyNotExists", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));

    }
    
    @Test
    /*
     * 要删除的policy已经附加给了其他用户
     */
    public void test_OOSPolicy_DeletePolicy_PolicyAttachUser() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        
        String url2=internalDomain+"deletePolicy";
        String body2=createSystemPolicyParam(policyName, null, null);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(409, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(409, jo2.getInt("status"));
        assertEquals("DeleteConflict", jo2.getString("code"));
        assertEquals("The OOS policy with name "+policyName+" is attached.", jo2.getString("message"));
        assertEquals("oosPolicyIsAttached", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));

        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
    }

    @Test
    public void test_OOSPolicy_GetPolicy() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        String url2=internalDomain+"getPolicy";
        String body2=createSystemPolicyParam(policyName, null, null);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(200, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertNotNull(jo2.getString("policyId"));
        assertEquals("OOS", jo2.getString("accountId"));
        assertEquals(policyName, jo2.getString("policyName"));
        assertEquals("OOS", jo2.getString("scope"));
        assertEquals(policyDocument, jo2.getString("document"));
        assertEquals(description, jo2.getString("description"));
        assertNotNull(jo2.getInt("createDate"));
        assertNotNull(jo2.getInt("updateDate"));
        assertEquals(jo2.getInt("createDate"), jo2.getInt("updateDate"));
        assertEquals("true", jo2.getString("isAttachable"));
        assertFalse(result2.second().contains("attachedTotal"));
    }
    
    @Test
    public void test_OOSPolicy_GetPolicy_Attached() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);

        String url2=internalDomain+"getPolicy";
        String body2=createSystemPolicyParam(policyName, null, null);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(200, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertNotNull(jo2.getString("policyId"));
        assertEquals("OOS", jo2.getString("accountId"));
        assertEquals(policyName, jo2.getString("policyName"));
        assertEquals("OOS", jo2.getString("scope"));
        assertEquals(policyDocument, jo2.getString("document"));
        assertEquals(description, jo2.getString("description"));
        assertNotNull(jo2.getInt("createDate"));
        assertNotNull(jo2.getInt("updateDate"));
        assertEquals(jo2.getInt("createDate"), jo2.getInt("updateDate"));
        assertEquals("true", jo2.getString("isAttachable"));
        assertEquals(1, jo2.getInt("attachedTotal"));
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        
    }
    
    @Test
    public void test_OOSPolicy_GetPolicy_NoParamPolicyName() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String policyName="oospolicy1";
        
        String url2=internalDomain+"getPolicy";
        String body2=createSystemPolicyParam(null, null, null);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(400, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(400, jo2.getInt("status"));
        assertEquals("InvalidArgument", jo2.getString("code"));
        assertEquals("PolicyName must not be empty.", jo2.getString("message"));
        assertEquals("policyNameEmpty", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));

    }
    
    @Test
    public void test_OOSPolicy_GetPolicy_PolicyNameEmpty() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String policyName="";
        
        String url2=internalDomain+"getPolicy";
        String body2=createSystemPolicyParam(policyName, null, null);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(400, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(400, jo2.getInt("status"));
        assertEquals("InvalidArgument", jo2.getString("code"));
        assertEquals("PolicyName must not be empty.", jo2.getString("message"));
        assertEquals("policyNameEmpty", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));

    }
    
    @Test
    /*
     * 系统策略不存在
     */
    public void test_OOSPolicy_GetPolicy_PolicyNotExist() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String policyName="oospolicy1";       
        String url2=internalDomain+"getPolicy";
        String body2=createSystemPolicyParam(policyName, null, null);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(404, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(404, jo2.getInt("status"));
        assertEquals("NoSuchEntity", jo2.getString("code"));
        assertEquals("The OOS policy with name "+policyName+" cannot be found.", jo2.getString("message"));
        assertEquals("oosPolicyNotExists", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));

    }
    
    @Test
    /*
     * 系统策略不存在，自定义策略存在
     */
    public void test_OOSPolicy_GetPolicy_PolicyNotExist2() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String policyName="oospolicy1";
        
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyDocument, 200);

        String url2=internalDomain+"getPolicy";
        String body2=createSystemPolicyParam(policyName, null, null);
        Pair<Integer, String> result2=internalRequest(url2, body2);
        assertEquals(404, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(404, jo2.getInt("status"));
        assertEquals("NoSuchEntity", jo2.getString("code"));
        assertEquals("The OOS policy with name "+policyName+" cannot be found.", jo2.getString("message"));
        assertEquals("oosPolicyNotExists", jo2.getJSONArray("errorMessages").getJSONObject(0).getString("messageCode"));

    }
    
    @Test
    public void test_OOSPolicy_ListPolicies() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String policyDocument1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+1),null);
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+2),null);
        String policyDocument3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+3),null);
        String policyDocument4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+4),null);
        String policyDocument5=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+5),null);
        
        List<String> policyDocuments= Arrays.asList(policyDocument1,policyDocument2,policyDocument3,policyDocument4,policyDocument5);
        
        for (int i = 1; i <= 5; i++) {

            String url=internalDomain+"createPolicy";
            String policyName="oospolicy"+i;
            String policyDocument=policyDocuments.get(i-1);
            String description="第"+i+"个系统策略的创建 aaa";
            String body=createSystemPolicyParam(policyName, policyDocument, description);
            Pair<Integer, String> result=internalRequest(url, body);
            assertEquals(200, result.first().intValue());
        }
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user2Name, "oospolicy3", 200);
        
        String url=internalDomain+"listPolicies";
        
//        String param="{\"marker\":\"OOS|oospolicy1\",\"maxItems\":1,\"policyName\":\"OOSpolicy\"}";
        String body="{\"policyName\":\"OOSpolicy\"}";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(false, jo.getBoolean("isTruncated"));
        assertFalse(result.second().contains("marker"));
        assertEquals(5, jo.getInt("total"));
        com.amazonaws.util.json.JSONArray list=jo.getJSONArray("list");
        for (int i = 1; i < list.length()+1; i++) {
            JSONObject jo1=(JSONObject) list.get(i-1);
            assertNotNull(jo1.getString("policyId"));
            assertEquals("OOS", jo1.getString("accountId"));
            assertEquals("oospolicy"+i, jo1.getString("policyName"));
            assertEquals("OOS", jo1.getString("scope"));
            assertEquals(policyDocuments.get(i-1), jo1.getString("document"));
            assertEquals("第"+i+"个系统策略的创建 aaa", jo1.getString("description"));
            assertNotNull(jo1.getInt("createDate"));
            assertNotNull(jo1.getInt("updateDate"));
            assertEquals(jo1.getInt("createDate"), jo1.getInt("updateDate"));
            assertEquals("true", jo1.getString("isAttachable"));
            if (i==3) {
                assertEquals(2, jo1.getInt("attachedTotal"));
            }else {
                assertFalse(jo1.toString().contains("attachedTotal"));
            }
        } 
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);

    }
    
    public void test_OOSPolicy_ListPolicies_NoParamPolicyName() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String policyDocument1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+1),null);
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+2),null);
        String policyDocument3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+3),null);
        String policyDocument4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+4),null);
        String policyDocument5=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+5),null);
        
        List<String> policyDocuments= Arrays.asList(policyDocument1,policyDocument2,policyDocument3,policyDocument4,policyDocument5);
        
        for (int i = 1; i <= 5; i++) {

            String url=internalDomain+"createPolicy";
            String policyName="oospolicy"+i;
            String policyDocument=policyDocuments.get(i-1);
            String description="第"+i+"个系统策略的创建 aaa";
            String body=createSystemPolicyParam(policyName, policyDocument, description);
            Pair<Integer, String> result=internalRequest(url, body);
            assertEquals(200, result.first().intValue());
        }
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user2Name, "oospolicy3", 200);
        
        String url=internalDomain+"listPolicies";
        
//        String param="{\"marker\":\"OOS|oospolicy1\",\"maxItems\":1,\"policyName\":\"OOSpolicy\"}";
        String body="{}";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(false, jo.getBoolean("isTruncated"));
        assertFalse(result.second().contains("marker"));
        assertEquals(5, jo.getInt("total"));
        com.amazonaws.util.json.JSONArray list=jo.getJSONArray("list");
        for (int i = 1; i < list.length()+1; i++) {
            JSONObject jo1=(JSONObject) list.get(i-1);
            assertNotNull(jo1.getString("policyId"));
            assertEquals("OOS", jo1.getString("accountId"));
            assertEquals("oospolicy"+i, jo1.getString("policyName"));
            assertEquals("OOS", jo1.getString("scope"));
            assertEquals(policyDocuments.get(i-1), jo1.getString("document"));
            assertEquals("第"+i+"个系统策略的创建 aaa", jo1.getString("description"));
            assertNotNull(jo1.getInt("createDate"));
            assertNotNull(jo1.getInt("updateDate"));
            assertEquals(jo1.getInt("createDate"), jo1.getInt("updateDate"));
            assertEquals("true", jo1.getString("isAttachable"));
            if (i==3) {
                assertEquals(2, jo1.getInt("attachedTotal"));
            }else {
                assertFalse(jo1.toString().contains("attachedTotal"));
            }
        } 
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
    }
    
    @Test
    public void test_OOSPolicy_ListPolicies_policyNameEmpty() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String policyDocument1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+1),null);
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+2),null);
        String policyDocument3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+3),null);
        String policyDocument4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+4),null);
        String policyDocument5=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+5),null);
        
        List<String> policyDocuments= Arrays.asList(policyDocument1,policyDocument2,policyDocument3,policyDocument4,policyDocument5);
        
        for (int i = 1; i <= 5; i++) {

            String url=internalDomain+"createPolicy";
            String policyName="oospolicy"+i;
            String policyDocument=policyDocuments.get(i-1);
            String description="第"+i+"个系统策略的创建 aaa";
            String body=createSystemPolicyParam(policyName, policyDocument, description);
            Pair<Integer, String> result=internalRequest(url, body);
            assertEquals(200, result.first().intValue());
        }
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user2Name, "oospolicy3", 200);
        
        String url=internalDomain+"listPolicies";
        
        String body="{\"policyName\":\"\"}";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(false, jo.getBoolean("isTruncated"));
        assertFalse(result.second().contains("marker"));
        assertEquals(5, jo.getInt("total"));
        com.amazonaws.util.json.JSONArray list=jo.getJSONArray("list");
        for (int i = 1; i < list.length()+1; i++) {
            JSONObject jo1=(JSONObject) list.get(i-1);
            assertNotNull(jo1.getString("policyId"));
            assertEquals("OOS", jo1.getString("accountId"));
            assertEquals("oospolicy"+i, jo1.getString("policyName"));
            assertEquals("OOS", jo1.getString("scope"));
            assertEquals(policyDocuments.get(i-1), jo1.getString("document"));
            assertEquals("第"+i+"个系统策略的创建 aaa", jo1.getString("description"));
            assertNotNull(jo1.getInt("createDate"));
            assertNotNull(jo1.getInt("updateDate"));
            assertEquals(jo1.getInt("createDate"), jo1.getInt("updateDate"));
            assertEquals("true", jo1.getString("isAttachable"));
            if (i==3) {
                assertEquals(2, jo1.getInt("attachedTotal"));
            }else {
                assertFalse(jo1.toString().contains("attachedTotal"));
            }
        } 
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
    }
    
    @Test
    public void test_OOSPolicy_ListPolicies_MaxItemsNoValue() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String policyDocument1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+1),null);
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+2),null);
        String policyDocument3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+3),null);
        String policyDocument4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+4),null);
        String policyDocument5=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+5),null);
        
        List<String> policyDocuments= Arrays.asList(policyDocument1,policyDocument2,policyDocument3,policyDocument4,policyDocument5);
        
        for (int i = 1; i <= 5; i++) {

            String url=internalDomain+"createPolicy";
            String policyName="oospolicy"+i;
            String policyDocument=policyDocuments.get(i-1);
            String description="第"+i+"个系统策略的创建 aaa";
            String body=createSystemPolicyParam(policyName, policyDocument, description);
            Pair<Integer, String> result=internalRequest(url, body);
            assertEquals(200, result.first().intValue());
        }
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user2Name, "oospolicy3", 200);
        
        String url=internalDomain+"listPolicies";
        
        String body="{\"maxItems\":\"\",\"policyName\":\"OOSpolicy\"}";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(false, jo.getBoolean("isTruncated"));
        assertFalse(result.second().contains("marker"));
        assertEquals(5, jo.getInt("total"));
        com.amazonaws.util.json.JSONArray list=jo.getJSONArray("list");
        for (int i = 1; i < list.length()+1; i++) {
            JSONObject jo1=(JSONObject) list.get(i-1);
            assertNotNull(jo1.getString("policyId"));
            assertEquals("OOS", jo1.getString("accountId"));
            assertEquals("oospolicy"+i, jo1.getString("policyName"));
            assertEquals("OOS", jo1.getString("scope"));
            assertEquals(policyDocuments.get(i-1), jo1.getString("document"));
            assertEquals("第"+i+"个系统策略的创建 aaa", jo1.getString("description"));
            assertNotNull(jo1.getInt("createDate"));
            assertNotNull(jo1.getInt("updateDate"));
            assertEquals(jo1.getInt("createDate"), jo1.getInt("updateDate"));
            assertEquals("true", jo1.getString("isAttachable"));
            if (i==3) {
                assertEquals(2, jo1.getInt("attachedTotal"));
            }else {
                assertFalse(jo1.toString().contains("attachedTotal"));
            }
        } 
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        
    }
    
    @Test
    public void test_OOSPolicy_ListPolicies_MaxItems0() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String policyDocument1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+1),null);
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+2),null);
        String policyDocument3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+3),null);
        String policyDocument4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+4),null);
        String policyDocument5=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+5),null);
        
        List<String> policyDocuments= Arrays.asList(policyDocument1,policyDocument2,policyDocument3,policyDocument4,policyDocument5);
        
        for (int i = 1; i <= 5; i++) {

            String url=internalDomain+"createPolicy";
            String policyName="oospolicy"+i;
            String policyDocument=policyDocuments.get(i-1);
            String description="第"+i+"个系统策略的创建 aaa";
            String body=createSystemPolicyParam(policyName, policyDocument, description);
            Pair<Integer, String> result=internalRequest(url, body);
            assertEquals(200, result.first().intValue());
        }
        
        String url=internalDomain+"listPolicies";
        String body="{\"maxItems\":0,\"policyName\":\"OOSpolicy\"}";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(true, jo.getBoolean("isTruncated"));
        assertFalse(result.second().contains("marker"));
        assertEquals(5, jo.getInt("total"));
        assertEquals(0, jo.getJSONArray("list").length());
    }
    
    @Test
    /*
     * marker -1
     */
    public void test_OOSPolicy_ListPolicies_MaxItemsNe1() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String policyDocument1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+1),null);
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+2),null);
        String policyDocument3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+3),null);
        String policyDocument4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+4),null);
        String policyDocument5=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+5),null);
        
        List<String> policyDocuments= Arrays.asList(policyDocument1,policyDocument2,policyDocument3,policyDocument4,policyDocument5);
        
        for (int i = 1; i <= 5; i++) {

            String url=internalDomain+"createPolicy";
            String policyName="oospolicy"+i;
            String policyDocument=policyDocuments.get(i-1);
            String description="第"+i+"个系统策略的创建 aaa";
            String body=createSystemPolicyParam(policyName, policyDocument, description);
            Pair<Integer, String> result=internalRequest(url, body);
            assertEquals(200, result.first().intValue());
        }
        String url=internalDomain+"listPolicies";
        String body="{\"maxItems\":-1,\"policyName\":\"OOSpolicy\"}";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(true, jo.getBoolean("isTruncated"));
        assertFalse(result.second().contains("marker"));
        assertEquals(5, jo.getInt("total"));
        assertEquals(0, jo.getJSONArray("list").length());
    }
    
    @Test
    public void test_OOSPolicy_ListPolicies_MarkerNoValue() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String policyDocument1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+1),null);
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+2),null);
        String policyDocument3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+3),null);
        String policyDocument4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+4),null);
        String policyDocument5=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+5),null);
        
        List<String> policyDocuments= Arrays.asList(policyDocument1,policyDocument2,policyDocument3,policyDocument4,policyDocument5);
        
        for (int i = 1; i <= 5; i++) {

            String url=internalDomain+"createPolicy";
            String policyName="oospolicy"+i;
            String policyDocument=policyDocuments.get(i-1);
            String description="第"+i+"个系统策略的创建 aaa";
            String body=createSystemPolicyParam(policyName, policyDocument, description);
            Pair<Integer, String> result=internalRequest(url, body);
            assertEquals(200, result.first().intValue());
        }
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user2Name, "oospolicy3", 200);
        
        String url=internalDomain+"listPolicies";
        
        String body="{\"marker\":\"\",\"maxItems\":100,\"policyName\":\"OOSpolicy\"}";
        
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(false, jo.getBoolean("isTruncated"));
        assertFalse(result.second().contains("marker"));
        assertEquals(5, jo.getInt("total"));
        com.amazonaws.util.json.JSONArray list=jo.getJSONArray("list");
        for (int i = 1; i < list.length()+1; i++) {
            JSONObject jo1=(JSONObject) list.get(i-1);
            assertNotNull(jo1.getString("policyId"));
            assertEquals("OOS", jo1.getString("accountId"));
            assertEquals("oospolicy"+i, jo1.getString("policyName"));
            assertEquals("OOS", jo1.getString("scope"));
            assertEquals(policyDocuments.get(i-1), jo1.getString("document"));
            assertEquals("第"+i+"个系统策略的创建 aaa", jo1.getString("description"));
            assertNotNull(jo1.getInt("createDate"));
            assertNotNull(jo1.getInt("updateDate"));
            assertEquals(jo1.getInt("createDate"), jo1.getInt("updateDate"));
            assertEquals("true", jo1.getString("isAttachable"));
            if (i==3) {
                assertEquals(2, jo1.getInt("attachedTotal"));
            }else {
                assertFalse(jo1.toString().contains("attachedTotal"));
            }
        } 
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
    }
    
    @Test
    public void test_OOSPolicy_ListPolicies_Marker0() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String policyDocument1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+1),null);
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+2),null);
        String policyDocument3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+3),null);
        String policyDocument4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+4),null);
        String policyDocument5=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+5),null);
        
        List<String> policyDocuments= Arrays.asList(policyDocument1,policyDocument2,policyDocument3,policyDocument4,policyDocument5);
        
        for (int i = 1; i <= 5; i++) {

            String url=internalDomain+"createPolicy";
            String policyName="oospolicy"+i;
            String policyDocument=policyDocuments.get(i-1);
            String description="第"+i+"个系统策略的创建 aaa";
            String body=createSystemPolicyParam(policyName, policyDocument, description);
            Pair<Integer, String> result=internalRequest(url, body);
            assertEquals(200, result.first().intValue());
        }
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user2Name, "oospolicy3", 200);
        
        String url=internalDomain+"listPolicies";
        
        String body="{\"marker\":0,\"maxItems\":100,\"policyName\":\"OOSpolicy\"}";
        
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(false, jo.getBoolean("isTruncated"));
        assertFalse(result.second().contains("marker"));
        assertEquals(5, jo.getInt("total"));
        com.amazonaws.util.json.JSONArray list=jo.getJSONArray("list");
        for (int i = 1; i < list.length()+1; i++) {
            JSONObject jo1=(JSONObject) list.get(i-1);
            assertNotNull(jo1.getString("policyId"));
            assertEquals("OOS", jo1.getString("accountId"));
            assertEquals("oospolicy"+i, jo1.getString("policyName"));
            assertEquals("OOS", jo1.getString("scope"));
            assertEquals(policyDocuments.get(i-1), jo1.getString("document"));
            assertEquals("第"+i+"个系统策略的创建 aaa", jo1.getString("description"));
            assertNotNull(jo1.getInt("createDate"));
            assertNotNull(jo1.getInt("updateDate"));
            assertEquals(jo1.getInt("createDate"), jo1.getInt("updateDate"));
            assertEquals("true", jo1.getString("isAttachable"));
            if (i==3) {
                assertEquals(2, jo1.getInt("attachedTotal"));
            }else {
                assertFalse(jo1.toString().contains("attachedTotal"));
            }
        } 
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
    }
    
    @Test
    public void test_OOSPolicy_ListPolicies_MaxItems5MarkerNormal() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String policyDocument1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+1),null);
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+2),null);
        String policyDocument3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+3),null);
        String policyDocument4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+4),null);
        String policyDocument5=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+5),null);
        String policyDocument6=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+6),null);
        String policyDocument7=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+7),null);
        String policyDocument8=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+8),null);
        String policyDocument9=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+9),null);
        
        List<String> policyDocuments1= Arrays.asList(policyDocument1,policyDocument2,policyDocument3,policyDocument4,policyDocument5);
        List<String> policyDocuments2= Arrays.asList(policyDocument6,policyDocument7,policyDocument8,policyDocument9);
        List<String> policyDocuments = new ArrayList<String>();
        policyDocuments.addAll(policyDocuments1);
        policyDocuments.addAll(policyDocuments2);
        
        for (int i = 1; i <= 9; i++) {

            String url=internalDomain+"createPolicy";
            String policyName="oospolicy"+i;
            String policyDocument=policyDocuments.get(i-1);
            String description="第"+i+"个系统策略的创建 aaa";
            String body=createSystemPolicyParam(policyName, policyDocument, description);
            Pair<Integer, String> result=internalRequest(url, body);
            assertEquals(200, result.first().intValue());
        }
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user2Name, "oospolicy3", 200);
        
        String url=internalDomain+"listPolicies";
        String body="{\"maxItems\":5,\"policyName\":\"OOSpolicy\"}";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(true, jo.getBoolean("isTruncated"));
        assertEquals("OOS|oospolicy5", jo.getString("marker"));
        assertEquals(9, jo.getInt("total"));
        com.amazonaws.util.json.JSONArray list=jo.getJSONArray("list");
        for (int i = 1; i < list.length()+1; i++) {
            JSONObject jo1=(JSONObject) list.get(i-1);
            assertNotNull(jo1.getString("policyId"));
            assertEquals("OOS", jo1.getString("accountId"));
            assertEquals("oospolicy"+i, jo1.getString("policyName"));
            assertEquals("OOS", jo1.getString("scope"));
            assertEquals(policyDocuments1.get(i-1), jo1.getString("document"));
            assertEquals("第"+i+"个系统策略的创建 aaa", jo1.getString("description"));
            assertNotNull(jo1.getInt("createDate"));
            assertNotNull(jo1.getInt("updateDate"));
            assertEquals(jo1.getInt("createDate"), jo1.getInt("updateDate"));
            assertEquals("true", jo1.getString("isAttachable"));
            if (i==3) {
                assertEquals(2, jo1.getInt("attachedTotal"));
            }else {
                assertFalse(jo1.toString().contains("attachedTotal"));
            }
        } 
        
        String body2="{\"marker\":\"OOS|oospolicy5\",\"maxItems\":5,\"policyName\":\"OOSpolicy\"}";
        Pair<Integer, String> result2=internalRequest(url, body2);
        assertEquals(200, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(false, jo2.getBoolean("isTruncated"));
        assertFalse(jo2.toString().contains("marker"));
        assertEquals(4, jo2.getInt("total"));
        
        com.amazonaws.util.json.JSONArray list2=jo2.getJSONArray("list");
        for (int i = 6; i < list2.length()+6; i++) {
            JSONObject jo1=(JSONObject) list2.get(i-6);
            assertNotNull(jo1.getString("policyId"));
            assertEquals("OOS", jo1.getString("accountId"));
            assertEquals("oospolicy"+i, jo1.getString("policyName"));
            assertEquals("OOS", jo1.getString("scope"));
            assertEquals(policyDocuments2.get(i-6), jo1.getString("document"));
            assertEquals("第"+i+"个系统策略的创建 aaa", jo1.getString("description"));
            assertNotNull(jo1.getInt("createDate"));
            assertNotNull(jo1.getInt("updateDate"));
            assertEquals(jo1.getInt("createDate"), jo1.getInt("updateDate"));
            assertEquals("true", jo1.getString("isAttachable"));
            assertFalse(jo1.toString().contains("attachedTotal"));

        } 
        
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);

    }
    
    @Test
    /*
     * marker不正确从头开始
     */
    public void test_OOSPolicy_ListPolicies_MarkerErrorValue() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String policyDocument1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+1),null);
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+2),null);
        String policyDocument3=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+3),null);
        String policyDocument4=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+4),null);
        String policyDocument5=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+5),null);
        String policyDocument6=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+6),null);
        String policyDocument7=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+7),null);
        String policyDocument8=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+8),null);
        String policyDocument9=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/group0"+9),null);
        
        List<String> policyDocuments1= Arrays.asList(policyDocument1,policyDocument2,policyDocument3,policyDocument4,policyDocument5);
        List<String> policyDocuments2= Arrays.asList(policyDocument6,policyDocument7,policyDocument8,policyDocument9);
        List<String> policyDocuments = new ArrayList<String>();
        policyDocuments.addAll(policyDocuments1);
        policyDocuments.addAll(policyDocuments2);
        
        for (int i = 1; i <= 9; i++) {

            String url=internalDomain+"createPolicy";
            String policyName="oospolicy"+i;
            String policyDocument=policyDocuments.get(i-1);
            String description="第"+i+"个系统策略的创建 aaa";
            String body=createSystemPolicyParam(policyName, policyDocument, description);
            Pair<Integer, String> result=internalRequest(url, body);
            assertEquals(200, result.first().intValue());
        }
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user2Name, "oospolicy3", 200);
        
        String url=internalDomain+"listPolicies";
        String body="{\"maxItems\":5,\"policyName\":\"OOSpolicy\"}";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(true, jo.getBoolean("isTruncated"));
        assertEquals("OOS|oospolicy5", jo.getString("marker"));
        assertEquals(9, jo.getInt("total"));
        com.amazonaws.util.json.JSONArray list=jo.getJSONArray("list");
        for (int i = 1; i < list.length()+1; i++) {
            JSONObject jo1=(JSONObject) list.get(i-1);
            assertNotNull(jo1.getString("policyId"));
            assertEquals("OOS", jo1.getString("accountId"));
            assertEquals("oospolicy"+i, jo1.getString("policyName"));
            assertEquals("OOS", jo1.getString("scope"));
            assertEquals(policyDocuments1.get(i-1), jo1.getString("document"));
            assertEquals("第"+i+"个系统策略的创建 aaa", jo1.getString("description"));
            assertNotNull(jo1.getInt("createDate"));
            assertNotNull(jo1.getInt("updateDate"));
            assertEquals(jo1.getInt("createDate"), jo1.getInt("updateDate"));
            assertEquals("true", jo1.getString("isAttachable"));
            if (i==3) {
                assertEquals(2, jo1.getInt("attachedTotal"));
            }else {
                assertFalse(jo1.toString().contains("attachedTotal"));
            }
        } 
        
        // marker不正确
        String body2="{\"marker\":\"OOS|OOSpolicy5\",\"maxItems\":5,\"policyName\":\"OOSpolicy\"}";
        Pair<Integer, String> result2=internalRequest(url, body2);
        assertEquals(200, result2.first().intValue());
        JSONObject jo2=new JSONObject(result2.second());
        assertEquals(true, jo2.getBoolean("isTruncated"));
        assertEquals("OOS|oospolicy5", jo2.getString("marker"));
        assertEquals(9, jo2.getInt("total"));
        
        com.amazonaws.util.json.JSONArray list2=jo2.getJSONArray("list");
        for (int i = 1; i < list2.length()+1; i++) {
            JSONObject jo1=(JSONObject) list2.get(i-1);
            assertNotNull(jo1.getString("policyId"));
            assertEquals("OOS", jo1.getString("accountId"));
            assertEquals("oospolicy"+i, jo1.getString("policyName"));
            assertEquals("OOS", jo1.getString("scope"));
            assertEquals(policyDocuments1.get(i-1), jo1.getString("document"));
            assertEquals("第"+i+"个系统策略的创建 aaa", jo1.getString("description"));
            assertNotNull(jo1.getInt("createDate"));
            assertNotNull(jo1.getInt("updateDate"));
            assertEquals(jo1.getInt("createDate"), jo1.getInt("updateDate"));
            assertEquals("true", jo1.getString("isAttachable"));
            if (i==3) {
                assertEquals(2, jo1.getInt("attachedTotal"));
            }else {
                assertFalse(jo1.toString().contains("attachedTotal"));
            }
        } 
        
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, "oospolicy3", 200);

    }
    
    @Test
    /*
     * 创建系统策略，用IAM deletepolicy接口删除
     */
    public void test_OOSPolicy_IAMAPIDele_root() throws JSONException, org.json.JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        String xml=IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, "OOS", policyName, 403);
        org.json.JSONObject apijo=IAMTestUtils.ParseErrorToJson(xml);
        assertEquals("AccessDenied", apijo.getString("Code"));
        assertEquals("Policy is outside your own account.", apijo.getString("Message"));
        assertEquals("arn:ctyun:iam::OOS:policy/"+policyName, apijo.getString("Resource"));
    }
    
    @Test
    /*
     * 创建系统策略，用IAM deletepolicy接口删除
     */
    public void test_OOSPolicy_IAMAPIDele_user() throws JSONException, org.json.JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);

        String xml=IAMInterfaceTestUtils.DeletePolicy(user1accessKey, user1secretKey, "OOS", policyName, 403);
        org.json.JSONObject apijo=IAMTestUtils.ParseErrorToJson(xml);
        assertEquals("AccessDenied", apijo.getString("Code"));
        assertEquals("Policy is outside your own account.", apijo.getString("Message"));
        assertEquals("arn:ctyun:iam::OOS:policy/"+policyName, apijo.getString("Resource"));
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey,"OOS", user1Name, policyName, 200);
    }
    
    @Test
    /*
     * 创建系统策略，用IAM getpolicy
     */
    public void test_OOSPolicy_IAMAPIGet_Root() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:CreateGroup"),"Resource",Arrays.asList("arn:ctyun:iam::*:group/*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        String policyId=jo.getString("policyId");
        assertNotNull(policyId);
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        long createDate = (long) jo.get("createDate");
        long updateDate = (long) jo.get("updateDate");;
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        String xml=IAMInterfaceTestUtils.GetPolicy(accessKey, secretKey, "OOS", policyName, 200);
        JSONObject apiget= new JSONObject();
        apiget = ParseXmlToJson(xml, "GetPolicy");
        assertEquals(policyName,apiget.get("PolicyName"));
        assertEquals("arn:ctyun:iam::OOS:policy/"+policyName, apiget.get("Arn"));
        assertEquals("true",apiget.get("IsAttachable"));
        assertEquals(description,apiget.get("Description"));
        assertEquals("0",apiget.get("AttachmentCount"));
        assertEquals("OOS",apiget.get("Scope"));
        assertEquals(URLEncoder.encode(policyDocument),apiget.get("Document"));
        assertEquals(policyId,apiget.get("PolicyId")); 
        
        String utcCreateDate=longToUTC(createDate);
        String utcUpdateDate=longToUTC(updateDate);
        assertEquals(utcCreateDate,apiget.get("CreateDate")); 
        assertEquals(utcUpdateDate,apiget.get("UpdateDate")); 

    }
    
    @Test
    /*
     * 创建系统策略，用IAM getpolicy
     */
    public void test_OOSPolicy_IAMAPIGet_user() throws Exception {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        String policyId=jo.getString("policyId");
        assertNotNull(policyId);
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        long createDate = (long) jo.get("createDate");
        long updateDate = (long) jo.get("updateDate");;
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);

        Thread.sleep(3000);
        
        String xml=IAMInterfaceTestUtils.GetPolicy(user1accessKey, user1secretKey, "OOS", policyName, 200);
        JSONObject apiget= new JSONObject();
        apiget = ParseXmlToJson(xml, "GetPolicy");
        assertEquals(policyName,apiget.get("PolicyName"));
        assertEquals("arn:ctyun:iam::OOS:policy/"+policyName, apiget.get("Arn"));
        assertEquals("true",apiget.get("IsAttachable"));
        assertEquals(description,apiget.get("Description"));
        assertEquals("1",apiget.get("AttachmentCount"));
        assertEquals("OOS",apiget.get("Scope"));
        assertEquals(URLEncoder.encode(policyDocument),apiget.get("Document"));
        assertEquals(policyId,apiget.get("PolicyId")); 
        
        String utcCreateDate=longToUTC(createDate);
        String utcUpdateDate=longToUTC(updateDate);
        assertEquals(utcCreateDate,apiget.get("CreateDate")); 
        assertEquals(utcUpdateDate,apiget.get("UpdateDate")); 
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey,"OOS", user1Name, policyName, 200);

    }
    
    @Test
    /*
     * 创建系统策略，用IAM AttachUserPolicy、DetachUserPolicy、AttachGroupPolicy、DetachGroupPolicy
     */
    public void test_OOSPolicy_IAMAPIAttach_root() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        String policyId=jo.getString("policyId");
        assertNotNull(policyId);
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        long createDate = (long) jo.get("createDate");
        long updateDate = (long) jo.get("updateDate");;
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);

        
        String xml=IAMInterfaceTestUtils.GetPolicy(user1accessKey, user1secretKey, "OOS", policyName, 200);
        JSONObject apiget= new JSONObject();
        apiget = ParseXmlToJson(xml, "GetPolicy");
        assertEquals(policyName,apiget.get("PolicyName"));
        assertEquals("arn:ctyun:iam::OOS:policy/"+policyName, apiget.get("Arn"));
        assertEquals("true",apiget.get("IsAttachable"));
        assertEquals(description,apiget.get("Description"));
        assertEquals("1",apiget.get("AttachmentCount"));
        assertEquals("OOS",apiget.get("Scope"));
        assertEquals(URLEncoder.encode(policyDocument),apiget.get("Document"));
        assertEquals(policyId,apiget.get("PolicyId")); 
        String utcCreateDate=longToUTC(createDate);
        String utcUpdateDate=longToUTC(updateDate);
        assertEquals(utcCreateDate,apiget.get("CreateDate")); 
        assertEquals(utcUpdateDate,apiget.get("UpdateDate")); 
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey,"OOS", user1Name, policyName, 200);
        
        IAMInterfaceTestUtils.GetPolicy(user1accessKey, user1secretKey, "OOS", policyName, 403);
        
        // 
        String groupName="mygroup";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, "OOS", groupName, policyName, 200);
        
        String xml2=IAMInterfaceTestUtils.GetPolicy(user1accessKey, user1secretKey, "OOS", policyName, 200);
        JSONObject apiget2= new JSONObject();
        apiget2 = ParseXmlToJson(xml2, "GetPolicy");
        assertEquals(policyName,apiget2.get("PolicyName"));
        assertEquals("arn:ctyun:iam::OOS:policy/"+policyName, apiget2.get("Arn"));
        assertEquals("true",apiget2.get("IsAttachable"));
        assertEquals(description,apiget2.get("Description"));
        assertEquals("1",apiget2.get("AttachmentCount"));
        assertEquals("OOS",apiget2.get("Scope"));
        assertEquals(URLEncoder.encode(policyDocument),apiget2.get("Document"));
        assertEquals(policyId,apiget2.get("PolicyId")); 
        assertEquals(utcCreateDate,apiget2.get("CreateDate")); 
        assertEquals(utcUpdateDate,apiget2.get("UpdateDate"));
        
        IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, "OOS", groupName, policyName, 200);
        IAMInterfaceTestUtils.GetPolicy(user1accessKey, user1secretKey, "OOS", policyName, 403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, user1Name, 200);
        IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);
        
    }
    
    @Test
    /*
     * 创建系统策略，用IAM AttachUserPolicy、DetachUserPolicy、AttachGroupPolicy、DetachGroupPolicy
     */
    public void test_OOSPolicy_IAMAPIAttach_user() throws JSONException {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        String policyId=jo.getString("policyId");
        assertNotNull(policyId);
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        long createDate = (long) jo.get("createDate");
        long updateDate = (long) jo.get("updateDate");;
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user2Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(user2accessKey, user2secretKey, "OOS", user1Name, policyName, 200);

        
        String xml=IAMInterfaceTestUtils.GetPolicy(user1accessKey, user1secretKey, "OOS", policyName, 200);
        JSONObject apiget= new JSONObject();
        apiget = ParseXmlToJson(xml, "GetPolicy");
        assertEquals(policyName,apiget.get("PolicyName"));
        assertEquals("arn:ctyun:iam::OOS:policy/"+policyName, apiget.get("Arn"));
        assertEquals("true",apiget.get("IsAttachable"));
        assertEquals(description,apiget.get("Description"));
        assertEquals("2",apiget.get("AttachmentCount"));
        assertEquals("OOS",apiget.get("Scope"));
        assertEquals(URLEncoder.encode(policyDocument),apiget.get("Document"));
        assertEquals(policyId,apiget.get("PolicyId")); 
        String utcCreateDate=longToUTC(createDate);
        String utcUpdateDate=longToUTC(updateDate);
        assertEquals(utcCreateDate,apiget.get("CreateDate")); 
        assertEquals(utcUpdateDate,apiget.get("UpdateDate")); 
        
        IAMInterfaceTestUtils.DetachUserPolicy(user2accessKey, user2secretKey,"OOS", user1Name, policyName, 200);
        
        IAMInterfaceTestUtils.GetPolicy(user1accessKey, user1secretKey, "OOS", policyName, 403);
        
        // 
        String groupName="mygroup";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(user2accessKey, user2secretKey, "OOS", groupName, policyName, 200);
        
        String xml2=IAMInterfaceTestUtils.GetPolicy(user1accessKey, user1secretKey, "OOS", policyName, 200);
        JSONObject apiget2= new JSONObject();
        apiget2 = ParseXmlToJson(xml2, "GetPolicy");
        assertEquals(policyName,apiget2.get("PolicyName"));
        assertEquals("arn:ctyun:iam::OOS:policy/"+policyName, apiget2.get("Arn"));
        assertEquals("true",apiget2.get("IsAttachable"));
        assertEquals(description,apiget2.get("Description"));
        assertEquals("2",apiget2.get("AttachmentCount"));
        assertEquals("OOS",apiget2.get("Scope"));
        assertEquals(URLEncoder.encode(policyDocument),apiget2.get("Document"));
        assertEquals(policyId,apiget2.get("PolicyId")); 
        assertEquals(utcCreateDate,apiget2.get("CreateDate")); 
        assertEquals(utcUpdateDate,apiget2.get("UpdateDate"));
        
        IAMInterfaceTestUtils.DetachGroupPolicy(user2accessKey, user2secretKey, "OOS", groupName, policyName, 200);
        IAMInterfaceTestUtils.GetPolicy(user1accessKey, user1secretKey, "OOS", policyName, 403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, user1Name, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey,"OOS", user2Name, policyName, 200);
        IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);
    }
    
    @Test
    /*
     * 
     * IAM API 调用以下
     * ListAttachedUserPolicies、ListAttachedGroupPolicies可以列出被附加的系统策略 
     * ListEntitiesForPolicy可以查看当前账户被系统策略附加的实体
     * ListPolicies 
     */
    public void test_OOSPolicy_IAMAPIList_root() throws JSONException {
        
        // 创建 系统策略，自定义策略
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
         
        String policyName1="Localpolicy01";
        String policyName2="Localpolicy02";
        String policyDocument1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*User*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyDocument1, 200);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyDocument2, 200);
        
        String groupName="listgroup1";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name, 200);
        
        // 把系统策略和自定义策略授权给用户和组
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, "OOS", groupName, policyName, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName1, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        // list
        
        System.out.println("-------------------list----------------");
        String attachedUserPolicies=IAMInterfaceTestUtils.ListAttachedUserPolicies(accessKey, secretKey, user1Name, 200);
        JSONObject aupJo=ParseXmlToJson2(attachedUserPolicies, "ListAttachedUserPolicies");
        System.out.print(aupJo.toString());
        assertEquals("false",aupJo.get("IsTruncated"));
        JSONObject user1policy1 = aupJo.getJSONObject("AttachedPolicies").getJSONObject("member1");
        assertEquals(policyName2,user1policy1.get("PolicyName"));
        assertEquals("arn:ctyun:iam::"+accountId+":policy/"+policyName2, user1policy1.get("PolicyArn"));
        assertEquals("Local",user1policy1.get("Scope"));
        JSONObject user1policy2 = aupJo.getJSONObject("AttachedPolicies").getJSONObject("member2");
        assertEquals(policyName,user1policy2.get("PolicyName"));
        assertEquals("arn:ctyun:iam::OOS:policy/"+policyName, user1policy2.get("PolicyArn"));
        assertEquals("OOS",user1policy2.get("Scope"));
        assertEquals(description,user1policy2.get("Description"));
        
        String attachedGroupPolicies=IAMInterfaceTestUtils.ListAttachedGroupPolicies(accessKey, secretKey, groupName, 200);
        JSONObject agpJo=ParseXmlToJson2(attachedGroupPolicies, "ListAttachedGroupPolicies");
        assertEquals("false",agpJo.get("IsTruncated"));
        JSONObject group1policy1 = agpJo.getJSONObject("AttachedPolicies").getJSONObject("member1");
        assertEquals(policyName1,group1policy1.get("PolicyName"));
        assertEquals("arn:ctyun:iam::"+accountId+":policy/"+policyName1, group1policy1.get("PolicyArn"));
        assertEquals("Local",group1policy1.get("Scope"));
        JSONObject group1policy2 = agpJo.getJSONObject("AttachedPolicies").getJSONObject("member2");
        assertEquals(policyName,group1policy2.get("PolicyName"));
        assertEquals("arn:ctyun:iam::OOS:policy/"+policyName, group1policy2.get("PolicyArn"));
        assertEquals("OOS",group1policy2.get("Scope"));
        assertEquals(description,group1policy2.get("Description"));
        
        
        String entitiesPolicy=IAMInterfaceTestUtils.ListEntitiesForPolicy(accessKey, secretKey, "OOS", policyName, 200);
        JSONObject epJo=ParseXmlToJson2(entitiesPolicy, "ListEntitiesForPolicy");
        JSONObject policyUser = epJo.getJSONObject("PolicyUsers").getJSONObject("member1");
        JSONObject policyGroup = epJo.getJSONObject("PolicyGroups").getJSONObject("member1");
        assertEquals("false",epJo.get("IsTruncated"));
        assertEquals(user1Name,policyUser.get("UserName"));
        assertEquals(groupName, policyGroup.get("GroupName"));
        assertNotNull(policyUser.get("UserId"));
        assertNotNull(policyGroup.get("GroupId"));
        
        String listPolicies=IAMInterfaceTestUtils.ListPolicies(accessKey, secretKey, 200);
        JSONObject lpJo=ParseXmlToJson2(listPolicies, "ListPolicies");
        assertEquals("false",lpJo.get("IsTruncated"));
        JSONObject policy1= lpJo.getJSONObject("Policies").getJSONObject("member1");
        assertEquals(policyName1,policy1.get("PolicyName"));
        assertEquals("arn:ctyun:iam::"+accountId+":policy/"+policyName1, policy1.get("Arn"));
        assertEquals("true",policy1.get("IsAttachable"));
        assertEquals("1",policy1.get("AttachmentCount"));
        assertEquals("Local",policy1.get("Scope"));
        assertNotNull(policy1.get("CreateDate"));
        assertNotNull(policy1.get("UpdateDate")); 
        assertNotNull(policy1.get("PolicyId")); 
        JSONObject policy2= lpJo.getJSONObject("Policies").getJSONObject("member2");
        assertEquals(policyName2,policy2.get("PolicyName"));
        assertEquals("arn:ctyun:iam::"+accountId+":policy/"+policyName2, policy2.get("Arn"));
        assertEquals("true",policy2.get("IsAttachable"));
        assertEquals("1",policy2.get("AttachmentCount"));
        assertEquals("Local",policy2.get("Scope"));
        assertNotNull(policy2.get("CreateDate"));
        assertNotNull(policy2.get("UpdateDate")); 
        assertNotNull(policy2.get("PolicyId")); 
        JSONObject policy3= lpJo.getJSONObject("Policies").getJSONObject("member3");
        assertEquals(policyName,policy3.get("PolicyName"));
        assertEquals("arn:ctyun:iam::OOS:policy/"+policyName, policy3.get("Arn"));
        assertEquals("true",policy3.get("IsAttachable"));
        assertEquals(description,policy3.get("Description"));
        assertEquals("2",policy3.get("AttachmentCount"));
        assertEquals("OOS",policy3.get("Scope"));
        assertNotNull(policy3.get("CreateDate"));
        assertNotNull(policy3.get("UpdateDate")); 
        assertNotNull(policy3.get("PolicyId")); 
        
        // 清理环境
        IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, "OOS", groupName, policyName, 200);
        IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName1, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, user1Name, 200);
        IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);

    }
    
    @Test
    public void test_() throws InterruptedException {
        String policyName1 ="alloos";
        String policyString1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1,200);
        
        OOSAPIALLDeny(accessKey, secretKey, user1accessKey, user1secretKey);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        Thread.sleep(11000);
        
        OOSAPIALLAllow(user1accessKey, user1secretKey);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
        Thread.sleep(11000);
        OOSAPIALLDeny(accessKey, secretKey, user1accessKey, user1secretKey);
    }
    
    @Test
    /*
     * 
     * IAM API 调用以下
     * ListAttachedUserPolicies、ListAttachedGroupPolicies可以列出被附加的系统策略 
     * ListEntitiesForPolicy可以查看当前账户被系统策略附加的实体
     * ListPolicies 
     */
    public void test_OOSPolicy_IAMAPIList_user() throws JSONException {
        
        // 创建 系统策略，自定义策略
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="oospolicy1";
        String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String description="第一个系统策略的创建 aaa";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertNotNull(jo.getString("policyId"));
        assertEquals("OOS", jo.getString("accountId"));
        assertEquals(policyName, jo.getString("policyName"));
        assertEquals("OOS", jo.getString("scope"));
        assertEquals(policyDocument, jo.getString("document"));
        assertEquals(description, jo.getString("description"));
        assertNotNull(jo.get("createDate"));
        assertNotNull(jo.get("updateDate"));
        assertEquals(jo.get("createDate"), jo.get("updateDate"));
        assertEquals("true", jo.getString("isAttachable"));
         
        String policyName1="Localpolicy01";
        String policyName2="Localpolicy02";
        String policyDocument1=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*User*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        String policyDocument2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*Group*"),"Resource",Arrays.asList("arn:ctyun:iam::*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyDocument1, 200);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyDocument2, 200);
        
        String groupName="listgroup1";
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name, 200);
        
        // 把系统策略和自定义策略授权给用户和组
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, "OOS", groupName, policyName, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName1, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        
        // list       
        System.out.println("-------------------list----------------");
        String attachedUserPolicies=IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey, user1secretKey, user1Name, 200);
        JSONObject aupJo=ParseXmlToJson2(attachedUserPolicies, "ListAttachedUserPolicies");
        System.out.print(aupJo.toString());
        assertEquals("false",aupJo.get("IsTruncated"));
        JSONObject user1policy1 = aupJo.getJSONObject("AttachedPolicies").getJSONObject("member1");
        assertEquals(policyName2,user1policy1.get("PolicyName"));
        assertEquals("arn:ctyun:iam::"+accountId+":policy/"+policyName2, user1policy1.get("PolicyArn"));
        assertEquals("Local",user1policy1.get("Scope"));
        JSONObject user1policy2 = aupJo.getJSONObject("AttachedPolicies").getJSONObject("member2");
        assertEquals(policyName,user1policy2.get("PolicyName"));
        assertEquals("arn:ctyun:iam::OOS:policy/"+policyName, user1policy2.get("PolicyArn"));
        assertEquals("OOS",user1policy2.get("Scope"));
        assertEquals(description,user1policy2.get("Description"));
        
        String attachedGroupPolicies=IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey, user1secretKey, groupName, 200);
        JSONObject agpJo=ParseXmlToJson2(attachedGroupPolicies, "ListAttachedGroupPolicies");
        assertEquals("false",agpJo.get("IsTruncated"));
        JSONObject group1policy1 = agpJo.getJSONObject("AttachedPolicies").getJSONObject("member1");
        assertEquals(policyName1,group1policy1.get("PolicyName"));
        assertEquals("arn:ctyun:iam::"+accountId+":policy/"+policyName1, group1policy1.get("PolicyArn"));
        assertEquals("Local",group1policy1.get("Scope"));
        JSONObject group1policy2 = agpJo.getJSONObject("AttachedPolicies").getJSONObject("member2");
        assertEquals(policyName,group1policy2.get("PolicyName"));
        assertEquals("arn:ctyun:iam::OOS:policy/"+policyName, group1policy2.get("PolicyArn"));
        assertEquals("OOS",group1policy2.get("Scope"));
        assertEquals(description,group1policy2.get("Description"));
        
        
        String entitiesPolicy=IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey, user1secretKey, "OOS", policyName, 200);
        JSONObject epJo=ParseXmlToJson2(entitiesPolicy, "ListEntitiesForPolicy");
        JSONObject policyUser = epJo.getJSONObject("PolicyUsers").getJSONObject("member1");
        JSONObject policyGroup = epJo.getJSONObject("PolicyGroups").getJSONObject("member1");
        assertEquals("false",epJo.get("IsTruncated"));
        assertEquals(user1Name,policyUser.get("UserName"));
        assertEquals(groupName, policyGroup.get("GroupName"));
        assertNotNull(policyUser.get("UserId"));
        assertNotNull(policyGroup.get("GroupId"));
        
        String listPolicies=IAMInterfaceTestUtils.ListPolicies(user1accessKey, user1secretKey, 200);
        JSONObject lpJo=ParseXmlToJson2(listPolicies, "ListPolicies");
        assertEquals("false",lpJo.get("IsTruncated"));
        JSONObject policy1= lpJo.getJSONObject("Policies").getJSONObject("member1");
        assertEquals(policyName1,policy1.get("PolicyName"));
        assertEquals("arn:ctyun:iam::"+accountId+":policy/"+policyName1, policy1.get("Arn"));
        assertEquals("true",policy1.get("IsAttachable"));
        assertEquals("1",policy1.get("AttachmentCount"));
        assertEquals("Local",policy1.get("Scope"));
        assertNotNull(policy1.get("CreateDate"));
        assertNotNull(policy1.get("UpdateDate")); 
        assertNotNull(policy1.get("PolicyId")); 
        JSONObject policy2= lpJo.getJSONObject("Policies").getJSONObject("member2");
        assertEquals(policyName2,policy2.get("PolicyName"));
        assertEquals("arn:ctyun:iam::"+accountId+":policy/"+policyName2, policy2.get("Arn"));
        assertEquals("true",policy2.get("IsAttachable"));
        assertEquals("1",policy2.get("AttachmentCount"));
        assertEquals("Local",policy2.get("Scope"));
        assertNotNull(policy2.get("CreateDate"));
        assertNotNull(policy2.get("UpdateDate")); 
        assertNotNull(policy2.get("PolicyId")); 
        JSONObject policy3= lpJo.getJSONObject("Policies").getJSONObject("member3");
        assertEquals(policyName,policy3.get("PolicyName"));
        assertEquals("arn:ctyun:iam::OOS:policy/"+policyName, policy3.get("Arn"));
        assertEquals("true",policy3.get("IsAttachable"));
        assertEquals(description,policy3.get("Description"));
        assertEquals("2",policy3.get("AttachmentCount"));
        assertEquals("OOS",policy3.get("Scope"));
        assertNotNull(policy3.get("CreateDate"));
        assertNotNull(policy3.get("UpdateDate")); 
        assertNotNull(policy3.get("PolicyId")); 
        
        // 清理环境
        IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, "OOS", groupName, policyName, 200);
        IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName1, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, user1Name, 200);
        IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);

    }
    
    @Test
    public void test_OOSPolicy_Access_all() {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="AdministratorAccess";
        String policyDocument="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        String description="Provides full access to services and resources.";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
//        IAMAPIALLAllow(user1accessKey, user1secretKey);
//        OOSAPIALLAllow(user1accessKey, user1secretKey);
//        CloudTrailAPIALLAllow(user1accessKey, user1secretKey, "trail01", cloudtrailBucket, true);
        ManagementAPIALL(user1accessKey, user1secretKey, 200);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
//        IAMAPIALLDeny(accessKey, secretKey, user1accessKey, user1secretKey);
//        OOSAPIALLDeny(accessKey, secretKey, user1accessKey, user1secretKey);
//        CloudTrailAPIALLDeny(accessKey, secretKey, user1accessKey, user1secretKey, "trail01", cloudtrailBucket, true);
        ManagementAPIALL(user1accessKey, user1secretKey, 403);
        
    }
    
    @Test
    public void test_OOSPolicy_Access_iam_all() {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="OOSIAMFullAccess";
        String policyDocument="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"iam:*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        String description="Provides full access to IAM";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        IAMAPIALLAllow(user1accessKey, user1secretKey);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        IAMAPIALLDeny(accessKey, secretKey, user1accessKey, user1secretKey);
    }
    
    @Test
    public void test_OOSPolicy_Access_iam_readOnly() {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="IAMReadOnlyAccess";
        String policyDocument="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": [\n" + 
                "                \"iam:Get*\",\n" + 
                "                \"iam:List*\"\n" + 
                "            ],\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        String description="Provides read only access to IAM";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
    
        IAMAPIALLReadOnly(accessKey, secretKey, user1accessKey, user1secretKey);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        IAMAPIALLDeny(accessKey, secretKey, user1accessKey, user1secretKey);
    }
    
    @Test
    public void test_OOSPolicy_Access_iam_changePasswd() {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        
        String url=internalDomain+"createPolicy";
        String policyName="IAMUserChangePassword";
        String policyDocument="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": [\n" + 
                "                \"iam:ChangePassword\",\n" + 
                "                \"iam:GetAccountPasswordPolicy\"\n" + 
                "            ],\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        String description="Provides the ability for an IAM user to change their own password.";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        
        IAMInterfaceTestUtils.CreateLoginProfile(accessKey, secretKey, user1Name, "a12345678", 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        
        IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey, user1secretKey, 200);
        IAMInterfaceTestUtils.ChangePassword(user1accessKey, user1secretKey, user1Name, "a12345678", "b12345678", 200);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey, user1secretKey, 403);
        IAMInterfaceTestUtils.ChangePassword(user1accessKey, user1secretKey, user1Name, "a12345678", "b12345678", 403);
        
        IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);
    }
    
    @Test
    public void test_OOSPolicy_Access_oos_all() {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="OOSFullAccess";
        String policyDocument="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"oos:*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        String description="Provides full access to all buckets.";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        
        OOSAPIALLAllow(user1accessKey, user1secretKey);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        
        OOSAPIALLDeny(accessKey, secretKey, user1accessKey, user1secretKey);
    }
    
    @Test
    public void test_OOSPolicy_Access_oos_readOnly() {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="OOSReadOnlyAccess";
        String policyDocument="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": [\n" + 
                "                \"oos:Get*\",\n" + 
                "                \"oos:List*\"\n" + 
                "            ],\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        String description="Provides read only access to all buckets";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        OOSAPIReadOnly(accessKey, secretKey, user1accessKey, user1secretKey);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        OOSAPIALLDeny(accessKey, secretKey, user1accessKey, user1secretKey);
    
    }
    
    @Test
    public void test_OOSPolicy_Access_cloudtrail_all() {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="OOSCloudTrailFullAccess";
        String policyDocument="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": [\n" + 
                "                \"oos:CreateBucket\",\n" + 
                "                \"oos:DeleteBucket\",\n" + 
                "                \"oos:ListAllMyBuckets\",\n" + 
                "                \"oos:ListBucket\",\n" + 
                "                \"oos:GetObject\"\n" + 
                "            ],\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        },\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"cloudtrail:*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        String description="Provides full access to OOS CloudTrail";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        String trailName="mytrail";
        String bucketName=cloudtrailBucket;
        CloudTrailAPIALLAllow(user1accessKey, user1secretKey, trailName, bucketName, true);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        
        CloudTrailAPIALLDeny(accessKey, secretKey, user1accessKey, user1secretKey, trailName, bucketName, true);
    }
    
    @Test
    public void test_OOSPolicy_Access_cloudtrail_readOnly() {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="OOSCloudTrailReadOnlyAccess";
        String policyDocument="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": [\n" + 
                "                \"oos:GetObject\",\n" + 
                "                \"oos:ListAllMyBuckets\"\n" + 
                "            ],\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        },\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": [\n" + 
                "                \"cloudtrail:GetTrailStatus\",\n" + 
                "                \"cloudtrail:DescribeTrails\",\n" + 
                "                \"cloudtrail:LookupEvents\",\n" + 
                "                \"cloudtrail:GetEventSelectors\"\n" + 
                "            ],\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        String description="Provides read only access to OOS CloudTrail";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        String trailName="trail02";
        CloudTrailAPIReadOnly(accessKey, secretKey, user1accessKey, user1secretKey, trailName, cloudtrailBucket, true,200);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        
        CloudTrailAPIReadOnly(accessKey, secretKey, user1accessKey, user1secretKey, trailName, cloudtrailBucket, true,403);
        
        
    }
    
    @Test
    public void test_OOSPolicy_Access_management_all() {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="OOSStat";
        String policyDocument="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"statistics:*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        String description="Provides read only access to OOS CloudTrail";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        
        ManagementAPIALL(user1accessKey, user1secretKey, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        ManagementAPIALL(user1accessKey, user1secretKey, 403);
        
    }
    
    @Test
    /*
     * 自定义和系统策略混合
     */
    public void test_OOSPolicy_Access_iam_allow_allow() {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="OOSFullAccess";
        String policyDocument="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"oos:*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        String description="Provides full access to all buckets.";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        
        String localPolicyName="CloudTrailall";
        String localpolicyString= "{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": [\n" + 
                "                \"oos:CreateBucket\",\n" + 
                "                \"oos:DeleteBucket\",\n" + 
                "                \"oos:ListAllMyBuckets\",\n" + 
                "                \"oos:ListBucket\",\n" + 
                "                \"oos:GetObject\"\n" + 
                "            ],\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        },\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"cloudtrail:*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, localPolicyName, localpolicyString, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, localPolicyName, 200);
 
        OOSAPIALLAllow(user1accessKey, user1secretKey);
        CloudTrailAPIALLAllow(user1accessKey, user1secretKey, "trail02", cloudtrailBucket, true);
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, localPolicyName, 200);
 
        
    }
    
    @Test
    /*
     * 自定义和系统策略混合
     * 系统允许，自定义拒绝
     */
    public void test_OOSPolicy_Access_iam_allow_deny() {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="OOSFullAccess";
        String policyDocument="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"oos:*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        String description="Provides full access to all buckets.";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        
        String localPolicyName="DenyPut";
        String localpolicyString= "{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Deny\",\n" + 
                "            \"Action\": \"oos:PutBucket\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, localPolicyName, localpolicyString, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, localPolicyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put("http", "oos-cd.ctyunapi.cn", 80, "V2", "cd", user1accessKey, user1secretKey, "yx-bucket-3", null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> delbucket2=OOSAPITestUtils.Bucket_Delete("http", "oos-cd.ctyunapi.cn", 80, "V2", "cd", user1accessKey, user1secretKey, "yx-bucket-3", null);
        assertEquals(403, delbucket2.first().intValue());
        System.out.println(delbucket2.second());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, localPolicyName, 200);
 
    }
    
    @Test
    /*
     * 自定义和系统策略混合
     * 系统拒绝，自定义允许
     */
    public void test_OOSPolicy_Access_iam_allow_deny2() {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        String url=internalDomain+"createPolicy";
        String policyName="DenyDelete";
        String policyDocument="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Deny\",\n" + 
                "            \"Action\": \"oos:*Delete*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        String description="Provides full access to all buckets.";
        String body=createSystemPolicyParam(policyName, policyDocument, description);
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        
        String localPolicyName="Allow";
        String localpolicyString= "{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"oos:*Bucket*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, localPolicyName, localpolicyString, 200);
        
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, localPolicyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put("http", "oos-cd.ctyunapi.cn", 80, "V2", "cd", user1accessKey, user1secretKey, "yx-bucket-3", null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, "OOS", user1Name, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, localPolicyName, 200);
    }
    
    public static void initTag() throws IOException, InterruptedException {
//      HBaseAdmin globalHbaseAdmin = new HBaseAdmin(globalConf);
//      
//      HBaseUserToTag.dropTable(GlobalHHZConfig.getConfig());
//      HBaseUserToTag.createTable(globalHbaseAdmin);
//      HBaseVSNTag.dropTable(GlobalHHZConfig.getConfig());
//      HBaseVSNTag.createTable(globalHbaseAdmin);
//      Thread.sleep(1000);
      
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
    
    public static void addUsrToRole(List<String> scope) throws Exception {
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
    
    public void IAMAPIALLAllow(String ak,String sk) {
        String groupName="group14";
        String userName="user14";
        
        IAMInterfaceTestUtils.CreateGroup(ak, sk, groupName, 200);
        IAMInterfaceTestUtils.CreateUser(ak, sk, userName, 200);
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag1=new Pair<String, String>();
        tag1.first("team");
        tag1.second("test");
        tags.add(tag1);
        IAMInterfaceTestUtils.TagUser(ak, sk, userName, tags, 200);
        String createAk=IAMInterfaceTestUtils.CreateAccessKey(ak, sk, userName, 200);
        String akId=getCreateAccessKey(createAk);
        IAMInterfaceTestUtils.UpdateAccessKey(ak, sk, akId, userName, "Inactive", 200);
        IAMInterfaceTestUtils.AddUserToGroup(ak, sk, groupName, userName, 200);
        
        
        IAMInterfaceTestUtils.CreateLoginProfile(ak, sk, userName, "a12345678", 200);
        IAMInterfaceTestUtils.UpdateLoginProfile(ak, sk, userName, "b12345678", 200);
//        IAMInterfaceTestUtils.ChangePassword(ak, sk, userName, "b12345678", "c12345678", 200);
        
        IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(ak, sk, 200);

        String virtualMFADeviceName="mfa2";
        String mfaString=IAMInterfaceTestUtils.CreateVirtualMFADevice(ak, sk, virtualMFADeviceName, 200);
        Pair<String, String> devicePair=getcreateVirtualMFADevice(mfaString);
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        IAMInterfaceTestUtils.EnableMFADevice(ak, sk, userName, accountId, virtualMFADeviceName, codesPair.first(), codesPair.second(), 200);
        
        String policyName="oosall";
        String policyString="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"oos:*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        IAMInterfaceTestUtils.CreatePolicy(ak, sk, policyName, policyString, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(ak, sk, accountId, groupName, policyName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(ak, sk, accountId, userName, policyName, 200);
        
        
        IAMInterfaceTestUtils.GetGroup(ak, sk, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(ak, sk, groupName, 200);
        IAMInterfaceTestUtils.GetUser(ak, sk, userName, 200);
        IAMInterfaceTestUtils.ListUsers(ak, sk, 200);
        IAMInterfaceTestUtils.ListUserTags(ak, sk, userName, 200);
        IAMInterfaceTestUtils.ListAccessKeys(ak, sk, userName, 200);
        IAMInterfaceTestUtils.ListGroupsForUser(ak, sk, userName, 200);
        IAMInterfaceTestUtils.GetLoginProfile(ak, sk, userName, 200);
        IAMInterfaceTestUtils.ListVirtualMFADevices(ak, sk, 200);
        IAMInterfaceTestUtils.ListMFADevices(ak, sk, userName, 200);
        IAMInterfaceTestUtils.GetAccountPasswordPolicy(ak, sk, 200);
        IAMInterfaceTestUtils.GetPolicy(ak, sk, accountId, policyName, 200);
        IAMInterfaceTestUtils.ListPolicies(ak, sk, 200);
        IAMInterfaceTestUtils.ListAttachedGroupPolicies(ak, sk, groupName, 200);
        IAMInterfaceTestUtils.ListAttachedUserPolicies(ak, sk, userName, 200);
        IAMInterfaceTestUtils.ListEntitiesForPolicy(ak, sk, accountId, policyName, 200);
        
        IAMInterfaceTestUtils.DetachUserPolicy(ak, sk, accountId, userName, policyName, 200);
        IAMInterfaceTestUtils.DetachGroupPolicy(ak, sk, accountId, groupName, policyName, 200);
        IAMInterfaceTestUtils.DeletePolicy(ak, sk, accountId, policyName, 200);
        IAMInterfaceTestUtils.DeactivateMFADevice(ak, sk, userName, accountId,virtualMFADeviceName , 200);
        IAMInterfaceTestUtils.DeleteVirtualMFADevice(ak, sk, accountId, virtualMFADeviceName, 200);
        IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(ak, sk, 200);
        IAMInterfaceTestUtils.DeleteLoginProfile(ak, sk, userName, 200);
        IAMInterfaceTestUtils.UntagUser(ak, sk, userName, Arrays.asList("team"), 200);
        IAMInterfaceTestUtils.DeleteAccessKey(ak, sk, akId, userName, 200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(ak, sk, groupName, userName, 200);
        IAMInterfaceTestUtils.DeleteUser(ak, sk, userName, 200);
        IAMInterfaceTestUtils.DeleteGroup(ak, sk, groupName, 200);
    }
    
    public void IAMAPIALLDeny(String rootak,String rootsk,String ak,String sk) {
        String groupName="group14";
        String userName="user14";
        
        IAMInterfaceTestUtils.CreateGroup(ak, sk, groupName, 403);
        IAMInterfaceTestUtils.CreateUser(ak, sk, userName, 403);
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag1=new Pair<String, String>();
        tag1.first("team");
        tag1.second("test");
        tags.add(tag1);
        IAMInterfaceTestUtils.TagUser(ak, sk, userName, tags, 403);
        IAMInterfaceTestUtils.CreateAccessKey(ak, sk, userName, 403);

        IAMInterfaceTestUtils.CreateGroup(rootak, rootsk, groupName, 200);
        IAMInterfaceTestUtils.CreateUser(rootak, rootsk, userName, 200);
        IAMInterfaceTestUtils.TagUser(rootak, rootsk, userName, tags, 200);
        String createAk=IAMInterfaceTestUtils.CreateAccessKey(rootak, rootsk, userName, 200);
        String akId=getCreateAccessKey(createAk);
        
        IAMInterfaceTestUtils.UpdateAccessKey(ak, sk, akId, userName, "Inactive", 403);
        IAMInterfaceTestUtils.AddUserToGroup(ak, sk, groupName, userName, 403);
        
        IAMInterfaceTestUtils.CreateLoginProfile(ak, sk, userName, "a12345678", 403);
        IAMInterfaceTestUtils.CreateLoginProfile(rootak, rootsk, userName, "a12345678", 200);
        
        IAMInterfaceTestUtils.UpdateLoginProfile(ak, sk, userName, "b12345678", 403);
        IAMInterfaceTestUtils.UpdateLoginProfile(rootak, rootsk, userName, "b12345678", 200);
//        IAMInterfaceTestUtils.ChangePassword(ak, sk, userName, "b12345678", "c12345678", 200);
        
        IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(ak, sk, 403);
        IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(rootak, rootsk, 200);

        String virtualMFADeviceName="mfa2";
        IAMInterfaceTestUtils.CreateVirtualMFADevice(ak, sk, virtualMFADeviceName, 403);
                
        String mfaString=IAMInterfaceTestUtils.CreateVirtualMFADevice(rootak, rootsk, virtualMFADeviceName, 200);
        Pair<String, String> devicePair=getcreateVirtualMFADevice(mfaString);
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        IAMInterfaceTestUtils.EnableMFADevice(ak, sk, userName, accountId, virtualMFADeviceName, codesPair.first(), codesPair.second(), 403);
        IAMInterfaceTestUtils.EnableMFADevice(rootak, rootsk, userName, accountId, virtualMFADeviceName, codesPair.first(), codesPair.second(), 200);
        
        String policyName="oosall";
        String policyString="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"oos:*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        IAMInterfaceTestUtils.CreatePolicy(ak, sk, policyName, policyString, 403);
        IAMInterfaceTestUtils.CreatePolicy(rootak, rootsk, policyName, policyString, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(ak, sk, accountId, groupName, policyName, 403);
        IAMInterfaceTestUtils.AttachUserPolicy(ak, sk, accountId, userName, policyName, 403);
        
        
        IAMInterfaceTestUtils.GetGroup(ak, sk, groupName, 403);
        IAMInterfaceTestUtils.ListGroups(ak, sk, groupName, 403);
        IAMInterfaceTestUtils.GetUser(ak, sk, userName, 403);
        IAMInterfaceTestUtils.ListUsers(ak, sk, 403);
        IAMInterfaceTestUtils.ListUserTags(ak, sk, userName, 403);
        IAMInterfaceTestUtils.ListAccessKeys(ak, sk, userName, 403);
        IAMInterfaceTestUtils.ListGroupsForUser(ak, sk, userName, 403);
        IAMInterfaceTestUtils.GetLoginProfile(ak, sk, userName, 403);
        IAMInterfaceTestUtils.ListVirtualMFADevices(ak, sk, 403);
        IAMInterfaceTestUtils.ListMFADevices(ak, sk, userName, 403);
        IAMInterfaceTestUtils.GetAccountPasswordPolicy(ak, sk, 403);
        IAMInterfaceTestUtils.GetPolicy(ak, sk, accountId, policyName, 403);
        IAMInterfaceTestUtils.ListPolicies(ak, sk, 403);
        IAMInterfaceTestUtils.ListAttachedGroupPolicies(ak, sk, groupName, 403);
        IAMInterfaceTestUtils.ListAttachedUserPolicies(ak, sk, userName, 403);
        IAMInterfaceTestUtils.ListEntitiesForPolicy(ak, sk, accountId, policyName, 403);
        
        IAMInterfaceTestUtils.DetachUserPolicy(ak, sk, accountId, userName, policyName, 403);
        IAMInterfaceTestUtils.DetachGroupPolicy(ak, sk, accountId, groupName, policyName, 403);
        IAMInterfaceTestUtils.DeletePolicy(ak, sk, accountId, policyName, 403);
        IAMInterfaceTestUtils.DeactivateMFADevice(ak, sk, userName, accountId,virtualMFADeviceName , 403);
        IAMInterfaceTestUtils.DeleteVirtualMFADevice(ak, sk, accountId, virtualMFADeviceName, 403);
        IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(ak, sk, 403);
        IAMInterfaceTestUtils.DeleteLoginProfile(ak, sk, userName, 403);
        IAMInterfaceTestUtils.UntagUser(ak, sk, userName, Arrays.asList("team"), 403);
        IAMInterfaceTestUtils.DeleteAccessKey(ak, sk, akId, userName, 403);
        IAMInterfaceTestUtils.DeleteUser(ak, sk, userName, 403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(ak, sk, groupName, userName, 403);
        IAMInterfaceTestUtils.DeleteGroup(ak, sk, groupName, 403);
        
        IAMInterfaceTestUtils.DeletePolicy(rootak, rootsk, accountId, policyName, 200);
        IAMInterfaceTestUtils.DeactivateMFADevice(rootak, rootsk, userName, accountId,virtualMFADeviceName , 200);
        IAMInterfaceTestUtils.DeleteVirtualMFADevice(rootak, rootsk, accountId, virtualMFADeviceName, 200);
        IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(rootak, rootsk, 200);
        IAMInterfaceTestUtils.DeleteLoginProfile(rootak, rootsk, userName, 200);
        IAMInterfaceTestUtils.UntagUser(rootak, rootsk, userName, Arrays.asList("team"), 200);
        IAMInterfaceTestUtils.DeleteAccessKey(rootak, rootsk, akId, userName, 200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(rootak, rootsk, groupName, userName, 200);
        IAMInterfaceTestUtils.DeleteUser(rootak, rootsk, userName, 200);
        IAMInterfaceTestUtils.DeleteGroup(rootak, rootsk, groupName, 200);
    }
    
    public void IAMAPIALLReadOnly(String rootak,String rootsk,String ak,String sk) {
        String groupName="group14";
        String userName="user14";
        
        IAMInterfaceTestUtils.CreateGroup(ak, sk, groupName, 403);
        IAMInterfaceTestUtils.CreateUser(ak, sk, userName, 403);
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag1=new Pair<String, String>();
        tag1.first("team");
        tag1.second("test");
        tags.add(tag1);
        IAMInterfaceTestUtils.TagUser(ak, sk, userName, tags, 403);
        IAMInterfaceTestUtils.CreateAccessKey(ak, sk, userName, 403);

        IAMInterfaceTestUtils.CreateGroup(rootak, rootsk, groupName, 200);
        IAMInterfaceTestUtils.CreateUser(rootak, rootsk, userName, 200);
        IAMInterfaceTestUtils.TagUser(rootak, rootsk, userName, tags, 200);
        String createAk=IAMInterfaceTestUtils.CreateAccessKey(rootak, rootsk, userName, 200);
        String akId=getCreateAccessKey(createAk);
        
        IAMInterfaceTestUtils.UpdateAccessKey(ak, sk, akId, userName, "Inactive", 403);
        IAMInterfaceTestUtils.AddUserToGroup(ak, sk, groupName, userName, 403);
        
        IAMInterfaceTestUtils.CreateLoginProfile(ak, sk, userName, "a12345678", 403);
        IAMInterfaceTestUtils.CreateLoginProfile(rootak, rootsk, userName, "a12345678", 200);
        
        IAMInterfaceTestUtils.UpdateLoginProfile(ak, sk, userName, "b12345678", 403);
        IAMInterfaceTestUtils.UpdateLoginProfile(rootak, rootsk, userName, "b12345678", 200);
//        IAMInterfaceTestUtils.ChangePassword(ak, sk, userName, "b12345678", "c12345678", 200);
        
        IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(ak, sk, 403);
        IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(rootak, rootsk, 200);

        String virtualMFADeviceName="mfa2";
        IAMInterfaceTestUtils.CreateVirtualMFADevice(ak, sk, virtualMFADeviceName, 403);
                
        String mfaString=IAMInterfaceTestUtils.CreateVirtualMFADevice(rootak, rootsk, virtualMFADeviceName, 200);
        Pair<String, String> devicePair=getcreateVirtualMFADevice(mfaString);
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        IAMInterfaceTestUtils.EnableMFADevice(ak, sk, userName, accountId, virtualMFADeviceName, codesPair.first(), codesPair.second(), 403);
        IAMInterfaceTestUtils.EnableMFADevice(rootak, rootsk, userName, accountId, virtualMFADeviceName, codesPair.first(), codesPair.second(), 200);
        
        String policyName="oosall";
        String policyString="{\n" + 
                "    \"Version\": \"2012-10-17\",\n" + 
                "    \"Statement\": [\n" + 
                "        {\n" + 
                "            \"Effect\": \"Allow\",\n" + 
                "            \"Action\": \"oos:*\",\n" + 
                "            \"Resource\": \"*\"\n" + 
                "        }\n" + 
                "    ]\n" + 
                "}\n" + 
                "";
        IAMInterfaceTestUtils.CreatePolicy(ak, sk, policyName, policyString, 403);
        IAMInterfaceTestUtils.CreatePolicy(rootak, rootsk, policyName, policyString, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(ak, sk, accountId, groupName, policyName, 403);
        IAMInterfaceTestUtils.AttachUserPolicy(ak, sk, accountId, userName, policyName, 403);
        
        
        IAMInterfaceTestUtils.GetGroup(ak, sk, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(ak, sk, groupName, 200);
        IAMInterfaceTestUtils.GetUser(ak, sk, userName, 200);
        IAMInterfaceTestUtils.ListUsers(ak, sk, 200);
        IAMInterfaceTestUtils.ListUserTags(ak, sk, userName, 200);
        IAMInterfaceTestUtils.ListAccessKeys(ak, sk, userName, 200);
        IAMInterfaceTestUtils.ListGroupsForUser(ak, sk, userName, 200);
        IAMInterfaceTestUtils.GetLoginProfile(ak, sk, userName, 200);
        IAMInterfaceTestUtils.ListVirtualMFADevices(ak, sk, 200);
        IAMInterfaceTestUtils.ListMFADevices(ak, sk, userName, 200);
        IAMInterfaceTestUtils.GetAccountPasswordPolicy(ak, sk, 200);
        IAMInterfaceTestUtils.GetPolicy(ak, sk, accountId, policyName, 200);
        IAMInterfaceTestUtils.ListPolicies(ak, sk, 200);
        IAMInterfaceTestUtils.ListAttachedGroupPolicies(ak, sk, groupName, 200);
        IAMInterfaceTestUtils.ListAttachedUserPolicies(ak, sk, userName, 200);
        IAMInterfaceTestUtils.ListEntitiesForPolicy(ak, sk, accountId, policyName, 200);
        
        IAMInterfaceTestUtils.DetachUserPolicy(ak, sk, accountId, userName, policyName, 403);
        IAMInterfaceTestUtils.DetachGroupPolicy(ak, sk, accountId, groupName, policyName, 403);
        IAMInterfaceTestUtils.DeletePolicy(ak, sk, accountId, policyName, 403);
        IAMInterfaceTestUtils.DeactivateMFADevice(ak, sk, userName, accountId,virtualMFADeviceName , 403);
        IAMInterfaceTestUtils.DeleteVirtualMFADevice(ak, sk, accountId, virtualMFADeviceName, 403);
        IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(ak, sk, 403);
        IAMInterfaceTestUtils.DeleteLoginProfile(ak, sk, userName, 403);
        IAMInterfaceTestUtils.UntagUser(ak, sk, userName, Arrays.asList("team"), 403);
        IAMInterfaceTestUtils.DeleteAccessKey(ak, sk, akId, userName, 403);
        IAMInterfaceTestUtils.DeleteUser(ak, sk, userName, 403);
        IAMInterfaceTestUtils.RemoveUserFromGroup(ak, sk, groupName, userName, 403);
        IAMInterfaceTestUtils.DeleteGroup(ak, sk, groupName, 403);
        
        IAMInterfaceTestUtils.DeletePolicy(rootak, rootsk, accountId, policyName, 200);
        IAMInterfaceTestUtils.DeactivateMFADevice(rootak, rootsk, userName, accountId,virtualMFADeviceName , 200);
        IAMInterfaceTestUtils.DeleteVirtualMFADevice(rootak, rootsk, accountId, virtualMFADeviceName, 200);
        IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(rootak, rootsk, 200);
        IAMInterfaceTestUtils.DeleteLoginProfile(rootak, rootsk, userName, 200);
        IAMInterfaceTestUtils.UntagUser(rootak, rootsk, userName, Arrays.asList("team"), 200);
        IAMInterfaceTestUtils.DeleteAccessKey(rootak, rootsk, akId, userName, 200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(rootak, rootsk, groupName, userName, 200);
        IAMInterfaceTestUtils.DeleteUser(rootak, rootsk, userName, 200);
        IAMInterfaceTestUtils.DeleteGroup(rootak, rootsk, groupName, 200);
    }
    
   
    
    public void OOSAPIALLAllow(String accessKey,String secretKey) {
        
        String host="oos-cd.ctyunapi.cn";
        String regionName="cd";
        String httpOrHttps="https";
        int jettyPort=8444;
        String signVersion="V4";
        String bucketName1="yx-bucket-3";
        String bucketName2="yx-bucket-4";
        String dateregion1="yxregion1";
        String dateregion2="yxregion2";
     // 获取所有bucket列表
        Pair<Integer, String> listallmybucket=OOSAPITestUtils.Service_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, null);
        assertEquals(200, listallmybucket.first().intValue());
        System.out.println(listallmybucket.second());
        
        // 获取资源池中的索引位置和数据位置列表
        Pair<Integer, String> getregion=OOSAPITestUtils.Region_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, null);
        assertEquals(200, getregion.first().intValue());
        System.out.println(getregion.second());
        
        // 创建bucket
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", null);
        assertEquals(200, createbucket2.first().intValue());
        System.out.println(createbucket2.second());
//        
//        // 获取bucket的ACL信息
        Pair<Integer, String> getbucketacl=OOSAPITestUtils.Bucket_GetAcl(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketacl.first().intValue());
        System.out.println(getbucketacl.second());
        
        // 修改bucket acl属性
        HashMap<String, String> updateaclParams=new HashMap<String, String>();
        updateaclParams.put("x-amz-acl", "public-read-write");
        Pair<Integer, String> updatebucket=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", updateaclParams);
        assertEquals(200, updatebucket.first().intValue());
        System.out.println(updatebucket.second());
        
        // 获取bucket的索引位置和数据位置 
        Pair<Integer, String> getbucketlocation=OOSAPITestUtils.Bucket_GetLocation(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketlocation.first().intValue());
        System.out.println(getbucketlocation.second());
        
        // 创建，获取，删除bucketpolicy
        String policyString = "{" + "\"Version\": \"2012-10-17\","
                + "\"Id\": \"preventHotLinking\"," + "\"Statement\": [" + " {"
                + " \"Sid\": \"1\"," + "\"Effect\": \"Allow\","
                + "\"Principal\": {" + " \"AWS\": \"*\"" + "},"
                + "\"Action\": \"s3:ListBucket\","
                + "\"Resource\": \"arn:aws:s3:::" + bucketName2 + "\","
                + "}]}";
        Pair<Integer, String> putbucketpolicy=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, policyString, null);
        assertEquals(200, putbucketpolicy.first().intValue());
        System.out.println(putbucketpolicy.second());
        
        Pair<Integer, String> getbucketpolicy=OOSAPITestUtils.Bucket_GetPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketpolicy.first().intValue());
        System.out.println(getbucketpolicy.second());
        
        Pair<Integer, String> delbucketpolicy=OOSAPITestUtils.Bucket_DeletePolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, delbucketpolicy.first().intValue());
        System.out.println(delbucketpolicy.second());
        
        // 创建，获取，删除website
        Pair<Integer, String> putbucketwebsite=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, putbucketwebsite.first().intValue());
        System.out.println(putbucketwebsite.second());
        
        Pair<Integer, String> getbucketwebsite=OOSAPITestUtils.Bucket_GetWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketwebsite.first().intValue());
        System.out.println(getbucketwebsite.second());
        
        Pair<Integer, String> delbucketwebsite=OOSAPITestUtils.Bucket_DeleteWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, delbucketwebsite.first().intValue());
        System.out.println(delbucketwebsite.second());
        
        // 创建，获取logging
        Pair<Integer, String> putbucketlogging=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, bucketName2,"logs/",null);
        assertEquals(200, putbucketlogging.first().intValue());
        System.out.println(putbucketlogging.second());
        
        Pair<Integer, String> getbucketlogging=OOSAPITestUtils.Bucket_GetLogging(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketlogging.first().intValue());
        System.out.println(getbucketlogging.second());
        
        // 创建，获取，删除lifecycle
        Pair<Integer, String> putbucketlifecle=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2,"logs","Enabled",30, null);
        assertEquals(200, putbucketlifecle.first().intValue());
        System.out.println(putbucketlifecle.second());
        
        Pair<Integer, String> getbucketlifecle=OOSAPITestUtils.Bucket_GetLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketlifecle.first().intValue());
        System.out.println(getbucketlifecle.second());
        
        Pair<Integer, String> delbucketlifecle=OOSAPITestUtils.Bucket_DeleteLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(204, delbucketlifecle.first().intValue());
        System.out.println(delbucketlifecle.second());
        
        // 创建，获取cdn加速
        Pair<Integer, String> putbucketaccelerate=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(200, putbucketaccelerate.first().intValue());
        System.out.println(putbucketaccelerate.second());
        
        Pair<Integer, String> getbucketaccelerate=OOSAPITestUtils.Bucket_GetAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketaccelerate.first().intValue());
        System.out.println(getbucketaccelerate.second());
        
        // 创建，获取，删除cors 
        Pair<Integer, String> putbucketcors=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, putbucketcors.first().intValue());
        System.out.println(putbucketcors.second());
        
        Pair<Integer, String> getbucketcors=OOSAPITestUtils.Bucket_GetCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketcors.first().intValue());
        System.out.println(getbucketcors.second());
        
        Pair<Integer, String> delbucketcors=OOSAPITestUtils.Bucket_DeleteCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, delbucketcors.first().intValue());
        System.out.println(delbucketcors.second());
        
        // delete bucket
        Pair<Integer, String> delbucket=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(204, delbucket.first().intValue());
        System.out.println(delbucket.second());
        
        // put get head delete object
        String objectName="src.txt";
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, "first", null);
        assertEquals(200, putobject.first().intValue());
        System.out.println(putobject.second());
        
        Pair<Integer, String> getobject=OOSAPITestUtils.Object_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(200, getobject.first().intValue());
        System.out.println(getobject.second());
        
        int headobject=OOSAPITestUtils.Object_Head(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(200, headobject);
        
        Pair<Integer, String> delobject=OOSAPITestUtils.Object_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(204, delobject.first().intValue());
        System.out.println(delobject.second());
        
        // post object
        Pair<Integer, String> postobject=OOSAPITestUtils.Object_Post(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, "post.txt", null);
        assertEquals(204, postobject.first().intValue());
        System.out.println(postobject.second());
        
        // copy object
        String objectName2="desc.txt";
        Pair<Integer, String> copyobject=OOSAPITestUtils.Object_Copy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, objectName2, null);
        assertEquals(200, copyobject.first().intValue());
        System.out.println(copyobject.second());
        
        // bucket中的object信息
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(200, listobjects.first().intValue());
        System.out.println(listobjects.second());
        
        // 分段上传，1.init 2.uploadpart,3.copy part,4.List Multipart Uploads,5.list part 6.Complete Multipart Upload,7.Abort Multipart Upload
        String objectName3="muli.txt";
        Pair<Integer, String> initmuli=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, null);
        assertEquals(200, initmuli.first().intValue());
        String uploadId=OOSAPITestUtils.getMultipartUploadId(initmuli.second());
        
        Pair<Integer, String> uploadpart=OOSAPITestUtils.Object_UploadPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, 1, "123", null);
        assertEquals(200, uploadpart.first().intValue());
        String etag1=uploadpart.second();
        Pair<Integer, String> copypart=OOSAPITestUtils.Object_CopyPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, 2, objectName, null);
        assertEquals(200, copypart.first().intValue());
        String etag2=OOSAPITestUtils.getCopyPartEtag(copypart.second());
        
        Pair<Integer, String> listMultipartUploads=OOSAPITestUtils.Bucket_ListMultipartUploads(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(200, listMultipartUploads.first().intValue());
        
        Pair<Integer, String> listpart=OOSAPITestUtils.Object_ListPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, null);
        assertEquals(200, listpart.first().intValue());
        System.out.println(listpart.second());
        
        Map<String, String> partEtagMap = new HashMap<String, String>();
        partEtagMap.put("1", etag1);
        partEtagMap.put("2", etag2);

        Pair<Integer, String> completemultipart=OOSAPITestUtils.Object_CompleteMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1,objectName3, uploadId, partEtagMap, null);
        assertEquals(200, completemultipart.first().intValue());
        System.out.println(completemultipart.second());
        
        String objectName4="muli2.txt";
        Pair<Integer, String> initmuli2=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName4, null);
        assertEquals(200, initmuli2.first().intValue());
        String uploadId2=OOSAPITestUtils.getMultipartUploadId(initmuli2.second());
        
        Pair<Integer, String> uploadpart2=OOSAPITestUtils.Object_UploadPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName4, uploadId2, 1, "123", null);
        assertEquals(200, uploadpart2.first().intValue());
        String etag3=uploadpart2.second();
        Pair<Integer, String> copypart2=OOSAPITestUtils.Object_CopyPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName4, uploadId2, 2, objectName, null);
        assertEquals(200, copypart2.first().intValue());
        String etag4=OOSAPITestUtils.getCopyPartEtag(copypart2.second());

        Pair<Integer, String> aboutmultipart=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName4, uploadId2, null);
        assertEquals(204, aboutmultipart.first().intValue());
        System.out.println(aboutmultipart.second());
        
        // delete mulit 
        Pair<Integer, String> delobjects=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, Arrays.asList(objectName,objectName2,objectName3,objectName4), null);
        assertEquals(200, delobjects.first().intValue());
        System.out.println(delobjects.second());
        
        // delete bucket
        Pair<Integer, String> delbucket2=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(204, delbucket2.first().intValue());
        System.out.println(delbucket2.second());
    }
    
    public void OOSAPIALLDeny(String rootak,String rootsk,String accessKey,String secretKey) {
        
        String host="oos-cd.ctyunapi.cn";
        String regionName="cd";
        String httpOrHttps="https";
        int jettyPort=8444;
        String signVersion="V4";
        String bucketName1="yx-bucket-3";
        String bucketName2="yx-bucket-4";
        String dateregion1="yxregion1";
        String dateregion2="yxregion2";
     // 获取所有bucket列表
        Pair<Integer, String> listallmybucket=OOSAPITestUtils.Service_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, null);
        assertEquals(403, listallmybucket.first().intValue());
        System.out.println(listallmybucket.second());
        
        // 获取资源池中的索引位置和数据位置列表
        Pair<Integer, String> getregion=OOSAPITestUtils.Region_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, null);
        assertEquals(403, getregion.first().intValue());
        System.out.println(getregion.second());
        
        // 创建bucket
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null, null, null, null, null);
        assertEquals(403, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> createbucket1root=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, null, null, null, null, null);
        assertEquals(200, createbucket1root.first().intValue());
        System.out.println(createbucket1root.second());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", null);
        assertEquals(403, createbucket2.first().intValue());
        System.out.println(createbucket2.second());
        
        Pair<Integer, String> createbucket2root=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", null);
        assertEquals(200, createbucket2root.first().intValue());
        System.out.println(createbucket2root.second());
//        
//        // 获取bucket的ACL信息
        Pair<Integer, String> getbucketacl=OOSAPITestUtils.Bucket_GetAcl(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketacl.first().intValue());
        System.out.println(getbucketacl.second());
        
        // 修改bucket acl属性
        HashMap<String, String> updateaclParams=new HashMap<String, String>();
        updateaclParams.put("x-amz-acl", "public-read-write");
        Pair<Integer, String> updatebucket=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", updateaclParams);
        assertEquals(403, updatebucket.first().intValue());
        System.out.println(updatebucket.second());
        
        // 获取bucket的索引位置和数据位置 
        Pair<Integer, String> getbucketlocation=OOSAPITestUtils.Bucket_GetLocation(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketlocation.first().intValue());
        System.out.println(getbucketlocation.second());
        
        // 创建，获取，删除bucketpolicy
        String policyString = "{" + "\"Version\": \"2012-10-17\","
                + "\"Id\": \"preventHotLinking\"," + "\"Statement\": [" + " {"
                + " \"Sid\": \"1\"," + "\"Effect\": \"Allow\","
                + "\"Principal\": {" + " \"AWS\": \"*\"" + "},"
                + "\"Action\": \"s3:ListBucket\","
                + "\"Resource\": \"arn:aws:s3:::" + bucketName2 + "\","
                + "}]}";
        Pair<Integer, String> putbucketpolicy=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, policyString, null);
        assertEquals(403, putbucketpolicy.first().intValue());
        System.out.println(putbucketpolicy.second());
        
        Pair<Integer, String> putbucketpolicyroot=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, policyString, null);
        assertEquals(200, putbucketpolicyroot.first().intValue());
        System.out.println(putbucketpolicyroot.second());
        
        Pair<Integer, String> getbucketpolicy=OOSAPITestUtils.Bucket_GetPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketpolicy.first().intValue());
        System.out.println(getbucketpolicy.second());
        
        Pair<Integer, String> delbucketpolicy=OOSAPITestUtils.Bucket_DeletePolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketpolicy.first().intValue());
        System.out.println(delbucketpolicy.second());
        
        // 创建，获取，删除website
        Pair<Integer, String> putbucketwebsite=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, putbucketwebsite.first().intValue());
        System.out.println(putbucketwebsite.second());
        
        Pair<Integer, String> putbucketwebsiteroot=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, null);
        assertEquals(200, putbucketwebsiteroot.first().intValue());
        System.out.println(putbucketwebsiteroot.second());
        
        Pair<Integer, String> getbucketwebsite=OOSAPITestUtils.Bucket_GetWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketwebsite.first().intValue());
        System.out.println(getbucketwebsite.second());
        
        Pair<Integer, String> delbucketwebsite=OOSAPITestUtils.Bucket_DeleteWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketwebsite.first().intValue());
        System.out.println(delbucketwebsite.second());
        
        // 创建，获取logging
        Pair<Integer, String> putbucketlogging=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, bucketName2,"logs/",null);
        assertEquals(403, putbucketlogging.first().intValue());
        System.out.println(putbucketlogging.second());
        
        Pair<Integer, String> putbucketloggingroot=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, bucketName2,"logs/",null);
        assertEquals(200, putbucketloggingroot.first().intValue());
        System.out.println(putbucketloggingroot.second());
        
        Pair<Integer, String> getbucketlogging=OOSAPITestUtils.Bucket_GetLogging(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketlogging.first().intValue());
        System.out.println(getbucketlogging.second());
        
        // 创建，获取，删除lifecycle
        Pair<Integer, String> putbucketlifecle=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2,"logs","Enabled",30, null);
        assertEquals(403, putbucketlifecle.first().intValue());
        System.out.println(putbucketlifecle.second());
        
        Pair<Integer, String> putbucketlifecleroot=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2,"logs","Enabled",30, null);
        assertEquals(200, putbucketlifecleroot.first().intValue());
        System.out.println(putbucketlifecleroot.second());
        
        Pair<Integer, String> getbucketlifecle=OOSAPITestUtils.Bucket_GetLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketlifecle.first().intValue());
        System.out.println(getbucketlifecle.second());
        
        Pair<Integer, String> delbucketlifecle=OOSAPITestUtils.Bucket_DeleteLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketlifecle.first().intValue());
        System.out.println(delbucketlifecle.second());
        
        // 创建，获取cdn加速
        Pair<Integer, String> putbucketaccelerate=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(403, putbucketaccelerate.first().intValue());
        System.out.println(putbucketaccelerate.second());
        
        Pair<Integer, String> putbucketaccelerateroot=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(200, putbucketaccelerateroot.first().intValue());
        System.out.println(putbucketaccelerateroot.second());
        
        Pair<Integer, String> getbucketaccelerate=OOSAPITestUtils.Bucket_GetAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketaccelerate.first().intValue());
        System.out.println(getbucketaccelerate.second());
        
        // 创建，获取，删除cors 
        Pair<Integer, String> putbucketcors=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, putbucketcors.first().intValue());
        System.out.println(putbucketcors.second());
        
        Pair<Integer, String> putbucketcorsroot=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, null);
        assertEquals(200, putbucketcorsroot.first().intValue());
        System.out.println(putbucketcorsroot.second());
        
        Pair<Integer, String> getbucketcors=OOSAPITestUtils.Bucket_GetCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, getbucketcors.first().intValue());
        System.out.println(getbucketcors.second());
        
        Pair<Integer, String> delbucketcors=OOSAPITestUtils.Bucket_DeleteCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketcors.first().intValue());
        System.out.println(delbucketcors.second());
         
        // delete bucket
        Pair<Integer, String> delbucket=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucket.first().intValue());
        System.out.println(delbucket.second());
        
        Pair<Integer, String> delbucketroot=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, null);
        assertEquals(204, delbucketroot.first().intValue());
        System.out.println(delbucketroot.second());
        
        // put get head delete object
        String objectName="src.txt";
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, "first", null);
        assertEquals(403, putobject.first().intValue());
        System.out.println(putobject.second());
        
        Pair<Integer, String> putobjectroot=OOSAPITestUtils.Object_Put(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, "first", null);
        assertEquals(200, putobjectroot.first().intValue());
        System.out.println(putobjectroot.second());
        
        Pair<Integer, String> getobject=OOSAPITestUtils.Object_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(403, getobject.first().intValue());
        System.out.println(getobject.second());
        
        int headobject=OOSAPITestUtils.Object_Head(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(403, headobject);
        
        Pair<Integer, String> delobject=OOSAPITestUtils.Object_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(403, delobject.first().intValue());
        System.out.println(delobject.second());
        
        Pair<Integer, String> delobjectroot=OOSAPITestUtils.Object_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, null);
        assertEquals(204, delobjectroot.first().intValue());
        System.out.println(delobjectroot.second());
        
        // post object
        Pair<Integer, String> postobject=OOSAPITestUtils.Object_Post(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, "post.txt", null);
        assertEquals(403, postobject.first().intValue());
        System.out.println(postobject.second());
        
        Pair<Integer, String> postobjectroot=OOSAPITestUtils.Object_Post(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, "post.txt", null);
        assertEquals(204, postobjectroot.first().intValue());
        System.out.println(postobjectroot.second());
        
        // copy object
        String objectName2="desc.txt";
        Pair<Integer, String> copyobject=OOSAPITestUtils.Object_Copy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, objectName2, null);
        assertEquals(403, copyobject.first().intValue());
        System.out.println(copyobject.second());
        
        Pair<Integer, String> copyobjectroot=OOSAPITestUtils.Object_Copy(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, objectName2, null);
        assertEquals(200, copyobjectroot.first().intValue());
        System.out.println(copyobjectroot.second());
        
        // bucket中的object信息
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(403, listobjects.first().intValue());
        System.out.println(listobjects.second());
        
        // 分段上传，1.init 2.uploadpart,3.copy part,4.List Multipart Uploads,5.list part 6.Complete Multipart Upload,7.Abort Multipart Upload
        String objectName3="muli.txt";
        Pair<Integer, String> initmuli=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, null);
        assertEquals(403, initmuli.first().intValue());
 
        Pair<Integer, String> initmuliroot=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, null);
        assertEquals(200, initmuliroot.first().intValue());
        String uploadId=OOSAPITestUtils.getMultipartUploadId(initmuliroot.second());
        
        Pair<Integer, String> uploadpart=OOSAPITestUtils.Object_UploadPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, 1, "123", null);
        assertEquals(403, uploadpart.first().intValue());
        Pair<Integer, String> copypart=OOSAPITestUtils.Object_CopyPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, 2, objectName, null);
        assertEquals(403, copypart.first().intValue());
        
        Pair<Integer, String> uploadpartroot=OOSAPITestUtils.Object_UploadPart(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, uploadId, 1, "123", null);
        assertEquals(200, uploadpartroot.first().intValue());
        String etag1=uploadpartroot.second();
        Pair<Integer, String> copypartroot=OOSAPITestUtils.Object_CopyPart(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, uploadId, 2, objectName, null);
        assertEquals(200, copypartroot.first().intValue());
        String etag2=OOSAPITestUtils.getCopyPartEtag(copypartroot.second());
        
        Pair<Integer, String> listMultipartUploads=OOSAPITestUtils.Bucket_ListMultipartUploads(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(403, listMultipartUploads.first().intValue());
        
        Pair<Integer, String> listpart=OOSAPITestUtils.Object_ListPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, null);
        assertEquals(403, listpart.first().intValue());
        System.out.println(listpart.second());
        
        Map<String, String> partEtagMap = new HashMap<String, String>();
        partEtagMap.put("1", etag1);
        partEtagMap.put("2", etag2);

        Pair<Integer, String> completemultipart=OOSAPITestUtils.Object_CompleteMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1,objectName3, uploadId, partEtagMap, null);
        assertEquals(403, completemultipart.first().intValue());
        System.out.println(completemultipart.second());
        
        Pair<Integer, String> aboutmultipart=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, null);
        assertEquals(403, aboutmultipart.first().intValue());
        System.out.println(aboutmultipart.second());
        
        Pair<Integer, String> aboutmultipartroot=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, uploadId, null);
        assertEquals(204, aboutmultipartroot.first().intValue());
        System.out.println(aboutmultipartroot.second());
        
        // delete mulit 
        Pair<Integer, String> delobjects=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, Arrays.asList(objectName,objectName2,objectName3), null);
        assertEquals(403, delobjects.first().intValue());
        System.out.println(delobjects.second());
        
        Pair<Integer, String> delobjectsroot=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, Arrays.asList(objectName,objectName2,objectName3), null);
        assertEquals(200, delobjectsroot.first().intValue());
        System.out.println(delobjectsroot.second());
        
        // delete bucket
        Pair<Integer, String> delbucket2=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(403, delbucket2.first().intValue());
        System.out.println(delbucket2.second());
        
        Pair<Integer, String> delbucket2root=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, null);
        assertEquals(204, delbucket2root.first().intValue());
        System.out.println(delbucket2root.second());
    }
    
    public void OOSAPIReadOnly(String rootak,String rootsk,String accessKey,String secretKey) {
        
        String host="oos-cd.ctyunapi.cn";
        String regionName="cd";
        String httpOrHttps="https";
        int jettyPort=8444;
        String signVersion="V4";
        String bucketName1="yx-bucket-3";
        String bucketName2="yx-bucket-4";
        String dateregion1="yxregion1";
        String dateregion2="yxregion2";
     // 获取所有bucket列表
        Pair<Integer, String> listallmybucket=OOSAPITestUtils.Service_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, null);
        assertEquals(200, listallmybucket.first().intValue());
        System.out.println(listallmybucket.second());
        
        // 获取资源池中的索引位置和数据位置列表
        Pair<Integer, String> getregion=OOSAPITestUtils.Region_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, null);
        assertEquals(200, getregion.first().intValue());
        System.out.println(getregion.second());
        
        // 创建bucket
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null, null, null, null, null);
        assertEquals(403, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> createbucket1root=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, null, null, null, null, null);
        assertEquals(200, createbucket1root.first().intValue());
        System.out.println(createbucket1root.second());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", null);
        assertEquals(403, createbucket2.first().intValue());
        System.out.println(createbucket2.second());
        
        Pair<Integer, String> createbucket2root=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", null);
        assertEquals(200, createbucket2root.first().intValue());
        System.out.println(createbucket2root.second());
//        
//        // 获取bucket的ACL信息
        Pair<Integer, String> getbucketacl=OOSAPITestUtils.Bucket_GetAcl(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketacl.first().intValue());
        System.out.println(getbucketacl.second());
        
        // 修改bucket acl属性
        HashMap<String, String> updateaclParams=new HashMap<String, String>();
        updateaclParams.put("x-amz-acl", "public-read-write");
        Pair<Integer, String> updatebucket=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", updateaclParams);
        assertEquals(403, updatebucket.first().intValue());
        System.out.println(updatebucket.second());
        
        // 获取bucket的索引位置和数据位置 
        Pair<Integer, String> getbucketlocation=OOSAPITestUtils.Bucket_GetLocation(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketlocation.first().intValue());
        System.out.println(getbucketlocation.second());
        
        // 创建，获取，删除bucketpolicy
        String policyString = "{" + "\"Version\": \"2012-10-17\","
                + "\"Id\": \"preventHotLinking\"," + "\"Statement\": [" + " {"
                + " \"Sid\": \"1\"," + "\"Effect\": \"Allow\","
                + "\"Principal\": {" + " \"AWS\": \"*\"" + "},"
                + "\"Action\": \"s3:ListBucket\","
                + "\"Resource\": \"arn:aws:s3:::" + bucketName2 + "\","
                + "}]}";
        Pair<Integer, String> putbucketpolicy=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, policyString, null);
        assertEquals(403, putbucketpolicy.first().intValue());
        System.out.println(putbucketpolicy.second());
        
        Pair<Integer, String> putbucketpolicyroot=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, policyString, null);
        assertEquals(200, putbucketpolicyroot.first().intValue());
        System.out.println(putbucketpolicyroot.second());
        
        Pair<Integer, String> getbucketpolicy=OOSAPITestUtils.Bucket_GetPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketpolicy.first().intValue());
        System.out.println(getbucketpolicy.second());
        
        Pair<Integer, String> delbucketpolicy=OOSAPITestUtils.Bucket_DeletePolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketpolicy.first().intValue());
        System.out.println(delbucketpolicy.second());
        
        // 创建，获取，删除website
        Pair<Integer, String> putbucketwebsite=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, putbucketwebsite.first().intValue());
        System.out.println(putbucketwebsite.second());
        
        Pair<Integer, String> putbucketwebsiteroot=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, null);
        assertEquals(200, putbucketwebsiteroot.first().intValue());
        System.out.println(putbucketwebsiteroot.second());
        
        Pair<Integer, String> getbucketwebsite=OOSAPITestUtils.Bucket_GetWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketwebsite.first().intValue());
        System.out.println(getbucketwebsite.second());
        
        Pair<Integer, String> delbucketwebsite=OOSAPITestUtils.Bucket_DeleteWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketwebsite.first().intValue());
        System.out.println(delbucketwebsite.second());
        
        // 创建，获取logging
        Pair<Integer, String> putbucketlogging=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, bucketName2,"logs/",null);
        assertEquals(403, putbucketlogging.first().intValue());
        System.out.println(putbucketlogging.second());
        
        Pair<Integer, String> putbucketloggingroot=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, bucketName2,"logs/",null);
        assertEquals(200, putbucketloggingroot.first().intValue());
        System.out.println(putbucketloggingroot.second());
        
        Pair<Integer, String> getbucketlogging=OOSAPITestUtils.Bucket_GetLogging(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketlogging.first().intValue());
        System.out.println(getbucketlogging.second());
        
        // 创建，获取，删除lifecycle
        Pair<Integer, String> putbucketlifecle=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2,"logs","Enabled",30, null);
        assertEquals(403, putbucketlifecle.first().intValue());
        System.out.println(putbucketlifecle.second());
        
        Pair<Integer, String> putbucketlifecleroot=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2,"logs","Enabled",30, null);
        assertEquals(200, putbucketlifecleroot.first().intValue());
        System.out.println(putbucketlifecleroot.second());
        
        Pair<Integer, String> getbucketlifecle=OOSAPITestUtils.Bucket_GetLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketlifecle.first().intValue());
        System.out.println(getbucketlifecle.second());
        
        Pair<Integer, String> delbucketlifecle=OOSAPITestUtils.Bucket_DeleteLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketlifecle.first().intValue());
        System.out.println(delbucketlifecle.second());
        
        // 创建，获取cdn加速
        Pair<Integer, String> putbucketaccelerate=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(403, putbucketaccelerate.first().intValue());
        System.out.println(putbucketaccelerate.second());
        
        Pair<Integer, String> putbucketaccelerateroot=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(200, putbucketaccelerateroot.first().intValue());
        System.out.println(putbucketaccelerateroot.second());
        
        Pair<Integer, String> getbucketaccelerate=OOSAPITestUtils.Bucket_GetAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketaccelerate.first().intValue());
        System.out.println(getbucketaccelerate.second());
        
        // 创建，获取，删除cors 
        Pair<Integer, String> putbucketcors=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, putbucketcors.first().intValue());
        System.out.println(putbucketcors.second());
        
        Pair<Integer, String> putbucketcorsroot=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, null);
        assertEquals(200, putbucketcorsroot.first().intValue());
        System.out.println(putbucketcorsroot.second());
        
        Pair<Integer, String> getbucketcors=OOSAPITestUtils.Bucket_GetCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketcors.first().intValue());
        System.out.println(getbucketcors.second());
        
        Pair<Integer, String> delbucketcors=OOSAPITestUtils.Bucket_DeleteCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucketcors.first().intValue());
        System.out.println(delbucketcors.second());
         
        // delete bucket
        Pair<Integer, String> delbucket=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(403, delbucket.first().intValue());
        System.out.println(delbucket.second());
        
        Pair<Integer, String> delbucketroot=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName2, null);
        assertEquals(204, delbucketroot.first().intValue());
        System.out.println(delbucketroot.second());
        
        // put get head delete object
        String objectName="src.txt";
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, "first", null);
        assertEquals(403, putobject.first().intValue());
        System.out.println(putobject.second());
        
        Pair<Integer, String> putobjectroot=OOSAPITestUtils.Object_Put(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, "first", null);
        assertEquals(200, putobjectroot.first().intValue());
        System.out.println(putobjectroot.second());
        
        Pair<Integer, String> getobject=OOSAPITestUtils.Object_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(200, getobject.first().intValue());
        System.out.println(getobject.second());
        
        int headobject=OOSAPITestUtils.Object_Head(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(200, headobject);
        
        Pair<Integer, String> delobject=OOSAPITestUtils.Object_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(403, delobject.first().intValue());
        System.out.println(delobject.second());
        
        Pair<Integer, String> delobjectroot=OOSAPITestUtils.Object_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, null);
        assertEquals(204, delobjectroot.first().intValue());
        System.out.println(delobjectroot.second());
        
        // post object
        Pair<Integer, String> postobject=OOSAPITestUtils.Object_Post(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, "post.txt", null);
        assertEquals(403, postobject.first().intValue());
        System.out.println(postobject.second());
        
        Pair<Integer, String> postobjectroot=OOSAPITestUtils.Object_Post(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, "post.txt", null);
        assertEquals(204, postobjectroot.first().intValue());
        System.out.println(postobjectroot.second());
        
        // copy object
        String objectName2="desc.txt";
        Pair<Integer, String> copyobject=OOSAPITestUtils.Object_Copy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, objectName2, null);
        assertEquals(403, copyobject.first().intValue());
        System.out.println(copyobject.second());
        
        Pair<Integer, String> copyobjectroot=OOSAPITestUtils.Object_Copy(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName, objectName2, null);
        assertEquals(200, copyobjectroot.first().intValue());
        System.out.println(copyobjectroot.second());
        
        // bucket中的object信息
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(200, listobjects.first().intValue());
        System.out.println(listobjects.second());
        
        // 分段上传，1.init 2.uploadpart,3.copy part,4.List Multipart Uploads,5.list part 6.Complete Multipart Upload,7.Abort Multipart Upload
        String objectName3="muli.txt";
        Pair<Integer, String> initmuli=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, null);
        assertEquals(403, initmuli.first().intValue());
 
        Pair<Integer, String> initmuliroot=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, null);
        assertEquals(200, initmuliroot.first().intValue());
        String uploadId=OOSAPITestUtils.getMultipartUploadId(initmuliroot.second());
        
        Pair<Integer, String> uploadpart=OOSAPITestUtils.Object_UploadPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, 1, "123", null);
        assertEquals(403, uploadpart.first().intValue());
        Pair<Integer, String> copypart=OOSAPITestUtils.Object_CopyPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, 2, objectName, null);
        assertEquals(403, copypart.first().intValue());
        
        Pair<Integer, String> uploadpartroot=OOSAPITestUtils.Object_UploadPart(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, uploadId, 1, "123", null);
        assertEquals(200, uploadpartroot.first().intValue());
        String etag1=uploadpartroot.second();
        Pair<Integer, String> copypartroot=OOSAPITestUtils.Object_CopyPart(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, uploadId, 2, objectName, null);
        assertEquals(200, copypartroot.first().intValue());
        String etag2=OOSAPITestUtils.getCopyPartEtag(copypartroot.second());
        
        Pair<Integer, String> listMultipartUploads=OOSAPITestUtils.Bucket_ListMultipartUploads(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(200, listMultipartUploads.first().intValue());
        
        Pair<Integer, String> listpart=OOSAPITestUtils.Object_ListPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, null);
        assertEquals(200, listpart.first().intValue());
        System.out.println(listpart.second());
        
        Map<String, String> partEtagMap = new HashMap<String, String>();
        partEtagMap.put("1", etag1);
        partEtagMap.put("2", etag2);

        Pair<Integer, String> completemultipart=OOSAPITestUtils.Object_CompleteMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1,objectName3, uploadId, partEtagMap, null);
        assertEquals(403, completemultipart.first().intValue());
        System.out.println(completemultipart.second());
        
        Pair<Integer, String> aboutmultipart=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, null);
        assertEquals(403, aboutmultipart.first().intValue());
        System.out.println(aboutmultipart.second());
        
        Pair<Integer, String> aboutmultipartroot=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, objectName3, uploadId, null);
        assertEquals(204, aboutmultipartroot.first().intValue());
        System.out.println(aboutmultipartroot.second());
        
        // delete mulit 
        Pair<Integer, String> delobjects=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, Arrays.asList(objectName,objectName2,objectName3), null);
        assertEquals(403, delobjects.first().intValue());
        System.out.println(delobjects.second());
        
        Pair<Integer, String> delobjectsroot=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, Arrays.asList(objectName,objectName2,objectName3), null);
        assertEquals(200, delobjectsroot.first().intValue());
        System.out.println(delobjectsroot.second());
        
        // delete bucket
        Pair<Integer, String> delbucket2=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(403, delbucket2.first().intValue());
        System.out.println(delbucket2.second());
        
        Pair<Integer, String> delbucket2root=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, rootak, rootsk, bucketName1, null);
        assertEquals(204, delbucket2root.first().intValue());
        System.out.println(delbucket2root.second());
    }
    
    public void CloudTrailAPIReadOnly(String rootak,String rootsk,String accessKey,String secretKey, String trailName,String bucketName,boolean isTarget, int code) {
        String endpointUrlStr="https://oos-cd-cloudtrail.ctyunapi.cn:9458/";
        String regionName="cd";
        
        Pair<Integer, String> createtrail=CloudTrailAPITestUtils.CreateTrail(endpointUrlStr, regionName, rootak, rootsk, trailName, bucketName, isTarget, null);
        assertEquals(200, createtrail.first().intValue());
        System.out.println(createtrail.second());
        
        Pair<Integer, String> describeTrails=CloudTrailAPITestUtils.DescribeTrails(endpointUrlStr, regionName, accessKey, secretKey, Arrays.asList(trailName), isTarget, null);
        assertEquals(code, describeTrails.first().intValue());
        System.out.println(describeTrails.second());
        
        Pair<Integer, String> getEventSelectors=CloudTrailAPITestUtils.GetEventSelectors(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(code, getEventSelectors.first().intValue());
        System.out.println(getEventSelectors.second());
        
        Pair<Integer, String> getTrailStatus=CloudTrailAPITestUtils.GetTrailStatus(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(code, getTrailStatus.first().intValue());
        System.out.println(getTrailStatus.second());
        
        Pair<Integer, String> lookupEvents=CloudTrailAPITestUtils.LookupEvents(endpointUrlStr, regionName, accessKey, secretKey,"EventSource","oos-cn-cloudtrail.ctyunapi.cn", isTarget, null);
        assertEquals(code, lookupEvents.first().intValue());
        System.out.println(lookupEvents.second());
        
        Pair<Integer, String> deleteTrail=CloudTrailAPITestUtils.DeleteTrail(endpointUrlStr, regionName, rootak, rootsk, trailName, isTarget, null);
        assertEquals(200, deleteTrail.first().intValue());
        System.out.println(deleteTrail.second());
    }
    
    
    
    public void CloudTrailAPIALLAllow(String accessKey,String secretKey, String trailName,String bucketName,boolean isTarget) {
        String endpointUrlStr="https://oos-cd-cloudtrail.ctyunapi.cn:9458/";
        String regionName="cd";
        
        Pair<Integer, String> createtrail=CloudTrailAPITestUtils.CreateTrail(endpointUrlStr, regionName, accessKey, secretKey, trailName, bucketName, isTarget, null);
        assertEquals(200, createtrail.first().intValue());
        System.out.println(createtrail.second());
        
        Pair<Integer, String> describeTrails=CloudTrailAPITestUtils.DescribeTrails(endpointUrlStr, regionName, accessKey, secretKey, Arrays.asList(trailName), isTarget, null);
        assertEquals(200, describeTrails.first().intValue());
        System.out.println(describeTrails.second());
        
        Pair<Integer, String> updateTrail=CloudTrailAPITestUtils.UpdateTrail(endpointUrlStr, regionName, accessKey, secretKey, trailName, bucketName, null, isTarget, null);
        assertEquals(200, updateTrail.first().intValue());
        System.out.println(updateTrail.second());
        
        Pair<Integer, String> putEventSelectors=CloudTrailAPITestUtils.PutEventSelectors(endpointUrlStr, regionName, accessKey, secretKey, trailName, "All", isTarget, null);
        assertEquals(200, putEventSelectors.first().intValue());
        System.out.println(putEventSelectors.second());
        
        Pair<Integer, String> getEventSelectors=CloudTrailAPITestUtils.GetEventSelectors(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(200, getEventSelectors.first().intValue());
        System.out.println(getEventSelectors.second());

        Pair<Integer, String> startLogging=CloudTrailAPITestUtils.StartLogging(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(200, startLogging.first().intValue());
        System.out.println(startLogging.second());
        
        Pair<Integer, String> getTrailStatus=CloudTrailAPITestUtils.GetTrailStatus(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(200, getTrailStatus.first().intValue());
        System.out.println(getTrailStatus.second());
        
        Pair<Integer, String> stopLogging=CloudTrailAPITestUtils.StopLogging(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(200, stopLogging.first().intValue());
        System.out.println(stopLogging.second());
        
        Pair<Integer, String> lookupEvents=CloudTrailAPITestUtils.LookupEvents(endpointUrlStr, regionName, accessKey, secretKey,"EventSource","oos-cn-cloudtrail.ctyunapi.cn", isTarget, null);
        assertEquals(200, lookupEvents.first().intValue());
        System.out.println(lookupEvents.second());
        
        Pair<Integer, String> deleteTrail=CloudTrailAPITestUtils.DeleteTrail(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(200, deleteTrail.first().intValue());
        System.out.println(deleteTrail.second());
    }
    
    public void CloudTrailAPIALLDeny(String rootak,String rootsk,String accessKey,String secretKey, String trailName,String bucketName,boolean isTarget) {
        String endpointUrlStr="https://oos-cd-cloudtrail.ctyunapi.cn:9458/";
        String regionName="cd";
        
        Pair<Integer, String> createtrail=CloudTrailAPITestUtils.CreateTrail(endpointUrlStr, regionName, accessKey, secretKey, trailName, bucketName, isTarget, null);
        assertEquals(403, createtrail.first().intValue());
        System.out.println(createtrail.second());
        
        Pair<Integer, String> createtrail2=CloudTrailAPITestUtils.CreateTrail(endpointUrlStr, regionName, rootak, rootsk, trailName, bucketName, isTarget, null);
        assertEquals(200, createtrail2.first().intValue());
        System.out.println(createtrail2.second());
        
        Pair<Integer, String> describeTrails=CloudTrailAPITestUtils.DescribeTrails(endpointUrlStr, regionName, accessKey, secretKey, Arrays.asList(trailName), isTarget, null);
        assertEquals(403, describeTrails.first().intValue());
        System.out.println(describeTrails.second());
        
        Pair<Integer, String> updateTrail=CloudTrailAPITestUtils.UpdateTrail(endpointUrlStr, regionName, accessKey, secretKey, trailName, bucketName, null, isTarget, null);
        assertEquals(403, updateTrail.first().intValue());
        System.out.println(updateTrail.second());
        
        Pair<Integer, String> putEventSelectors=CloudTrailAPITestUtils.PutEventSelectors(endpointUrlStr, regionName, accessKey, secretKey, trailName, "All", isTarget, null);
        assertEquals(403, putEventSelectors.first().intValue());
        System.out.println(putEventSelectors.second());
        
        Pair<Integer, String> getEventSelectors=CloudTrailAPITestUtils.GetEventSelectors(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(403, getEventSelectors.first().intValue());
        System.out.println(getEventSelectors.second());

        Pair<Integer, String> startLogging=CloudTrailAPITestUtils.StartLogging(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(403, startLogging.first().intValue());
        System.out.println(startLogging.second());
        
        Pair<Integer, String> getTrailStatus=CloudTrailAPITestUtils.GetTrailStatus(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(403, getTrailStatus.first().intValue());
        System.out.println(getTrailStatus.second());
        
        Pair<Integer, String> stopLogging=CloudTrailAPITestUtils.StopLogging(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(403, stopLogging.first().intValue());
        System.out.println(stopLogging.second());
        
        Pair<Integer, String> lookupEvents=CloudTrailAPITestUtils.LookupEvents(endpointUrlStr, regionName, accessKey, secretKey,"EventSource","oos-cn-cloudtrail.ctyunapi.cn", isTarget, null);
        assertEquals(403, lookupEvents.first().intValue());
        System.out.println(lookupEvents.second());
        
        Pair<Integer, String> deleteTrail=CloudTrailAPITestUtils.DeleteTrail(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(403, deleteTrail.first().intValue());
        System.out.println(deleteTrail.second());
        
        Pair<Integer, String> deleteTrail2=CloudTrailAPITestUtils.DeleteTrail(endpointUrlStr, regionName, rootak, rootsk, trailName, isTarget, null);
        assertEquals(200, deleteTrail2.first().intValue());
        System.out.println(deleteTrail2.second());
    }
    
    public void ManagementAPIALL(String ak,String sk,int code) {
        String httpOrHttps="https"; 
        String host="oos-cd.ctyunapi.cn";
        int port=9462; 
        String signVersion="V4";
        String today = TimeUtils.toYYYY_MM_dd(new Date());
        
        Pair<Integer, String> getUsage=ManagementAPITestUtils.GetUsage(httpOrHttps, host, port, signVersion, ak, sk, today, today, null, "byDay", null);
        assertEquals(code, getUsage.first().intValue());
        
        Pair<Integer, String> getAvailBW=ManagementAPITestUtils.GetAvailBW(httpOrHttps, host, port, signVersion, ak, sk, today+"-00-05", today+"-08-05", "yxregion1", null);
        assertEquals(code, getAvailBW.first().intValue());
        
        Pair<Integer, String> getBandwidth=ManagementAPITestUtils.GetBandwidth(httpOrHttps, host, port, signVersion, ak, sk, today+"-00-05", today+"-00-10", null, null);
        assertEquals(code, getBandwidth.first().intValue());
        
        Pair<Integer, String> getConnection=ManagementAPITestUtils.GetConnection(httpOrHttps, host, port, signVersion, ak, sk, today+"-00-05", today+"-00-10", null, null);
        assertEquals(code, getConnection.first().intValue());
        
        Pair<Integer, String> getCapacity=ManagementAPITestUtils.GetCapacity(httpOrHttps, host, port, signVersion, ak, sk, today, today, null, "byHour", "yxregion1", null);
        assertEquals(code, getCapacity.first().intValue());
        
        Pair<Integer, String> getDeleteCapacity=ManagementAPITestUtils.GetDeleteCapacity(httpOrHttps, host, port, signVersion, ak, sk, today, today, null, "byDay", "yxregion1", null);
        assertEquals(code, getDeleteCapacity.first().intValue());
        
        Pair<Integer, String> getTraffics=ManagementAPITestUtils.GetTraffics(httpOrHttps, host, port, signVersion, ak, sk,today, today, null, "by5min", "yxregion1", "all", "internet", "direct", null);
        assertEquals(code, getTraffics.first().intValue());
        
        Pair<Integer, String> getAvailableBandwidth=ManagementAPITestUtils.GetAvailableBandwidth(httpOrHttps, host, port, signVersion, ak, sk,today, today, "by5min", "yxregion1", "inbound", "noninternet", null);
        assertEquals(code, getAvailableBandwidth.first().intValue());
        
        Pair<Integer, String> getRequests=ManagementAPITestUtils.GetRequests(httpOrHttps, host, port, signVersion, ak, sk,today, today, null, "byDay", "yxregion1", "all", "put", null);
        assertEquals(code, getRequests.first().intValue());
        
        Pair<Integer, String> getReturnCode=ManagementAPITestUtils.GetReturnCode(httpOrHttps, host, port, signVersion, ak, sk,today, today, null, "byDay", "yxregion1", "all", "get", "Response500", null);
        assertEquals(code, getReturnCode.first().intValue());
        
        Pair<Integer, String> getConcurrentConnection=ManagementAPITestUtils.GetConcurrentConnection(httpOrHttps, host, port, signVersion, ak, sk,today, today, null, "by5min", "yxregion1", "all", null);
        assertEquals(code, getConcurrentConnection.first().intValue());
    }
    
    
    
    public Pair<Integer, String> internalRequest(String urlstr,String body) {
        Pair<Integer, String> result= new Pair<Integer, String>();
        try {      
            URL url= new URL(urlstr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoInput(true);
            conn.setDoOutput(true);
            if (body!=null) {

                try {
                    OutputStream wr = conn.getOutputStream();
                    
                    wr.write(body.getBytes());
                    wr.flush();
                    wr.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }  
            conn.connect();
            int code = conn.getResponseCode();
            System.out.println("code="+code);
            result.first(code);
            String xml="";
            if (code==200) {
                xml=IOUtils.toString(conn.getInputStream());
                
            }else {
                xml= IOUtils.toString(conn.getErrorStream());
            }
            System.out.println(xml);
            result.second(xml);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }
    
    public String createSystemPolicyParam(String policyName,String policyDocument,String description){
        
        JSONObject jObject= new JSONObject();
        try {
            if (policyName!=null) {
                jObject.put("policyName", policyName);
            }
            if (policyDocument!=null) {
                jObject.put("policyDocument", policyDocument);
            }
            if (description!=null) {
                jObject.put("description", description);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return jObject.toString();
    }
    
    public static JSONObject ParseXmlToJson(String xml, String actions) {
        
        try {
        
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = null ;
            JSONObject jObject= new JSONObject();
            if(actions.equals("CreatePolicy"))
                root = doc.getRootElement().getChild("CreatePolicyResult").getChild("Policy");
            if(actions.equals("GetPolicy"))
                root = doc.getRootElement().getChild("GetPolicyResult").getChild("Policy");                             
            List<Element> result=root.getChildren();
            System.out.println(result);
            Iterator<Element> iterator=result.iterator();
            
            while(iterator.hasNext()){
                Element root2 = iterator.next();
                
                String key=root2.getName();
                String value=root2.getValue();
                
                jObject.put(key, value);
                
            }

            return jObject;
            
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        return null;
        
    } 
    
public static JSONObject ParseXmlToJson2(String xml, String actions) {
        
        try {
        
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = null ;
            JSONObject jObject= new JSONObject();
            
            if(actions.equals("ListPolicies")){
                root = doc.getRootElement().getChild("ListPoliciesResult");
                String values = root.getChild("IsTruncated").getValue();
                jObject.put("IsTruncated", values);
                if(values.equals("true")){
                    String value2 = root.getChild("Marker").getValue();
                    jObject.put("Marker", value2);
                }
                
            }
                
            if(actions.equals("ListEntitiesForPolicy")){
                root = doc.getRootElement().getChild("ListEntitiesForPolicyResult");
                String values = root.getChild("IsTruncated").getValue();
                jObject.put("IsTruncated", values);
                if(values.equals("true")){
                    String value2 = root.getChild("Marker").getValue();
                    jObject.put("Marker", value2);
                }
                
           }
            
           if(actions.equals("ListAttachedGroupPolicies")){
                root = doc.getRootElement().getChild("ListAttachedGroupPoliciesResult");
                String values = root.getChild("IsTruncated").getValue();
                jObject.put("IsTruncated", values);
                if(values.equals("true")){
                    String value2 = root.getChild("Marker").getValue();
                    jObject.put("Marker", value2);
                }
                
           }
           if(actions.equals("ListAttachedUserPolicies")){
                root = doc.getRootElement().getChild("ListAttachedUserPoliciesResult");
                String values = root.getChild("IsTruncated").getValue();
                jObject.put("IsTruncated", values);
                if(values.equals("true")){
                    String value2 = root.getChild("Marker").getValue();
                    jObject.put("Marker", value2);
                }
                
           } 
                                            
            List<Element> result=root.getChildren();
            System.out.println(result);
            Iterator<Element> iterator=result.iterator();
            
            while(iterator.hasNext()){
                Element root2 = iterator.next();
                System.out.println(root2.getName());
                
                if(root2.getName().equals("Policies")){
                    List<Element> groups=root2.getChildren("member");
                    if(groups != null){
                        Iterator<Element> groupsterator=groups.iterator();
                        JSONObject jObject2= new JSONObject();
                        int i=1;
                        while(groupsterator.hasNext()){
                            Element root3 = groupsterator.next();
                            JSONObject jObject3= new JSONObject();
                            Element PolicyName=root3.getChild("PolicyName");
                            Element Arn=root3.getChild("Arn");
                            Element PolicyId=root3.getChild("PolicyId");
                            Element IsAttachable=root3.getChild("IsAttachable");
                            Element CreateDate=root3.getChild("CreateDate");
                            Element UpdateDate=root3.getChild("UpdateDate");
                            Element AttachmentCount=root3.getChild("AttachmentCount");
                            Element Scope=root3.getChild("Scope");
                            Element Description=root3.getChild("Description");
                            jObject3.put(PolicyName.getName(), PolicyName.getValue());
                            jObject3.put(Arn.getName(), Arn.getValue());
                            jObject3.put(PolicyId.getName(), PolicyId.getValue());
                            jObject3.put(IsAttachable.getName(), IsAttachable.getValue());
                            jObject3.put(CreateDate.getName(), CreateDate.getValue());
                            jObject3.put(UpdateDate.getName(), UpdateDate.getValue());
                            jObject3.put(AttachmentCount.getName(), AttachmentCount.getValue());
                            jObject3.put(Scope.getName(), Scope.getValue());
                            if (Description!=null) {
                                jObject3.put(Description.getName(), Description.getValue());
                            }

                            jObject2.put("member"+i, jObject3);
                            i++;
                        }
                        jObject.put("Policies", jObject2);
                    }
                }
                
                if(root2.getName().equals("PolicyUsers")){
                    List<Element> users=root2.getChildren("member");
                    if(users != null){
                        Iterator<Element> usersiterator=users.iterator();
                        JSONObject jObject2= new JSONObject();
                        int i=1;
                        while(usersiterator.hasNext()){                         
                            Element root3 = usersiterator.next();
                            System.out.println("root3:"+root3.getName());
                            JSONObject jObject3= new JSONObject();
                            Element userName=root3.getChild("UserName");
                            Element UserId=root3.getChild("UserId");                            
                            jObject3.put(userName.getName(), userName.getValue());                          
                            jObject3.put(UserId.getName(), UserId.getValue());
                            jObject2.put("member"+i, jObject3);                         
                            i++;                            
                        }
                        jObject.put("PolicyUsers", jObject2);   
                    }                   
                }
                
                if(root2.getName().equals("PolicyGroups")){
                    List<Element> users=root2.getChildren("member");
                    if(users != null){
                        Iterator<Element> usersiterator=users.iterator();
                        JSONObject jObject2= new JSONObject();
                        int i=1;
                        while(usersiterator.hasNext()){                         
                            Element root3 = usersiterator.next();
                            System.out.println("root3:"+root3.getName());
                            JSONObject jObject3= new JSONObject();
                            Element userName=root3.getChild("GroupName");
                            Element UserId=root3.getChild("GroupId");                           
                            jObject3.put(userName.getName(), userName.getValue());                          
                            jObject3.put(UserId.getName(), UserId.getValue());
                            jObject2.put("member"+i, jObject3);                         
                            i++;                            
                        }
                        jObject.put("PolicyGroups", jObject2);  
                    }                   
                }
                if(root2.getName().equals("AttachedPolicies")){
                    List<Element> users=root2.getChildren("member");
                    if(users != null){
                        Iterator<Element> usersiterator=users.iterator();
                        JSONObject jObject2= new JSONObject();
                        int i=1;
                        while(usersiterator.hasNext()){                         
                            Element root3 = usersiterator.next();
                            System.out.println("root3:"+root3.getName());
                            JSONObject jObject3= new JSONObject();
                            Element PolicyName=root3.getChild("PolicyName");
                            Element PolicyArn=root3.getChild("PolicyArn");  
                            Element Scope=root3.getChild("Scope");
                            Element Description=root3.getChild("Description");
                            jObject3.put(PolicyName.getName(), PolicyName.getValue());                          
                            jObject3.put(PolicyArn.getName(), PolicyArn.getValue());
                            jObject3.put(Scope.getName(), Scope.getValue());  
                            if (Description!=null) {
                                jObject3.put(Description.getName(), Description.getValue());
                            }
                            jObject2.put("member"+i, jObject3);                         
                            i++;                            
                        }
                        jObject.put("AttachedPolicies", jObject2);  
                    }                   
                }
            }

            return jObject;
            
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        return null;
        
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
    
    public Pair<String, String> getcreateVirtualMFADevice(String xml) {
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
            Pair<String, String> pair = new Pair<String, String>();
            pair.first(SerialNumber);
            pair.second(Base32StringSeed);
            return pair;
        } catch (Exception e) {
            // TODO: handle exception
        }
        
        return null;
    }
    
    public Pair<String, String> CreateIdentifyingCode(String secret) {
        Pair<String, String> codePair = new Pair<String, String>();
        int WINDOW_SIZE = 3;
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);
        long t = System.currentTimeMillis() / 1000L / 30L;
        for (int i = -WINDOW_SIZE; i <= WINDOW_SIZE; ++i) {
            long hash1 = generateCode(decodedKey, t + i);
            long hash2 = generateCode(decodedKey, t + i + 1);
            String code1=String.valueOf(hash1);
            String code2=String.valueOf(hash2);
            if (code1.length()<6) {
                String prefix="";
                for (int j = 0; j < 6-code1.length(); j++) {
                    prefix+="0";
                }
                code1=prefix+code1;
            }
            if (code2.length()<6) {
                String prefix="";
                for (int j = 0; j < 6-code2.length(); j++) {
                    prefix+="0";
                }
                code2=prefix+code2;
            }
            codePair.first(code1);
            codePair.second(code2);
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
    
    public String longToUTC(long time) {
        SimpleDateFormat sf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sf.setTimeZone(TimeZone.getTimeZone("UTC"));
        String utctime=sf.format(time);
        return utctime;
    }

}
