package cn.ctyun.oos.iam.test.InternalAPI;

import static org.junit.Assert.*;

import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.io.IOUtils;
import org.apache.hadoop.hbase.client.HConnection;
import org.apache.hadoop.hbase.client.HTableInterface;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.util.Bytes;
import org.eclipse.jetty.util.UrlEncoded;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xml.sax.InputSource;

import com.amazonaws.util.json.JSONException;
import com.amazonaws.util.json.JSONObject;

import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.hbase.HBaseConnectionManager;
import cn.ctyun.oos.hbase.HBaseUtil;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class LoginAndCheckDateTest {
    private static String ownerName = "root_user1@test.com";
    public static final String accessKey="userak1";
    public static final String secretKey="usersk1";
    public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();
    
    public static String user1Name="user1";
    public static String accountId1="3fdmxmc3pqvmp";
    public static final String internalDomain="http://oos-cd-iam.ctyunapi.cn:9097/internal/";

    public static String base32StringSeed="H6CI7ONEYL6SSDUY4YVWW3ZR7XRFYQFSM62P36XXQTZZVQZQE7I6WZWLUUUZEOFA";
    
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
//        CleanAndCreateUser();
    }

    @Before
    public void setUp() throws Exception {
    }
    
   
    
    public static void CleanAndCreateUser() throws Exception {
//        IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);
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
        
        String userName=user1Name;
        String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        assertEquals(200, resultPair.first().intValue());
        
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
        Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, createPasswd.first().intValue());
    }
    
    @Test
    public void CreateAndEnableMFA() {
        IAMTestUtils.TrancateTable(IAMTestUtils.iammfaDeviceTable);
        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::"+accountId1+":mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        System.out.println("base32StringSeed="+base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName="+user1Name+"&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
    }

    @Test
    public void test_Login() {
        
        String accountId="3fdmxmc3pqvmp";
        String userName=user1Name;
        String password="a12345678";
        String mFACode=null;
            
        String body=createLoginParam(accountId, userName, password, mFACode);
        String url=internalDomain+"login";

        internalRequest(url, body);
    }
    
    @Test
    public void test_checkMFACode() throws JSONException {
        String accountId="3fdmxmc3pqvmp";
        String userName=user1Name;
        String password=null;
        String mFACode=getMFACode(base32StringSeed);
            
        String body=createLoginParam(accountId, userName, password, mFACode);
        String url=internalDomain+"checkCode";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(true, jo.getBoolean("multiFactorAuthPresent"));
                
    }
    
    @Test
    /*
     * 没有accoutId参数
     */
    public void test_checkMFACode_NoAccountIdParam() throws JSONException {
        String accountId=null;
        String userName=user1Name;
        String password=null;
        String mFACode=getMFACode(base32StringSeed);
            
        String body=createLoginParam(accountId, userName, password, mFACode);
        String url=internalDomain+"checkCode";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.get("code"));
        assertEquals("AccountId must not be empty.", jo.get("message"));
    }
    
    @Test
    /*
     * accoutId在数据库里不存在
     */
    public void test_checkMFACode_AccountIdNotExists() throws JSONException {
        String accountId="3fdmxmc5pqvmp";
        String userName=user1Name;
        String password=null;
        String mFACode=getMFACode(base32StringSeed);
            
        String body=createLoginParam(accountId, userName, password, mFACode);
        String url=internalDomain+"checkCode";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(400, result.first().intValue());
//        JSONObject jo=new JSONObject(result.second());
//        assertEquals(400, jo.getInt("status"));
//        assertEquals("InvalidArgument", jo.get("code"));
//        assertEquals("AccountId must not be empty.", jo.get("message"));
    }
    
    @Test
    /*
     * 没有user参数
     */
    public void test_checkMFACode_NoUserParam() throws JSONException {
        String accountId="3fdmxmc3pqvmp";
        String userName=null;
        String password=null;
        String mFACode=getMFACode(base32StringSeed);
            
        String body=createLoginParam(accountId, userName, password, mFACode);
        String url=internalDomain+"checkCode";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.get("code"));
        assertEquals("UserName must be not empty.", jo.get("message"));
    }
    
    @Test
    /*
     * user不在数据库中
     */
    public void test_checkMFACode_UserNotExists() throws JSONException {
        String accountId="3fdmxmc3pqvmp";
        String userName="test100";
        String password=null;
        String mFACode=getMFACode(base32StringSeed);
            
        String body=createLoginParam(accountId, userName, password, mFACode);
        String url=internalDomain+"checkCode";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.get("code"));
        assertEquals("UserName must be not empty.", jo.get("message"));
    }
    
    @Test
    /*
     * 没有mfacode参数
     */
    public void test_checkMFACode_NomFACodeParam() throws JSONException {
        String accountId="3fdmxmc3pqvmp";
        String userName=user1Name;
        String password=null;
        String mFACode=null;
            
        String body=createLoginParam(accountId, userName, password, mFACode);
        String url=internalDomain+"checkCode";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.get("code"));
        assertEquals("MFACode must be not empty.", jo.get("message"));
        
    }
    
    @Test
    /*
     * mfacode 填写错误
     */
    public void test_checkMFACode_mFACodeError() throws JSONException {
        String accountId="3fdmxmc3pqvmp";
        String userName=user1Name;
        String password=null;
        String mFACode="123456";
            
        String body=createLoginParam(accountId, userName, password, mFACode);
        String url=internalDomain+"checkCode";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(false, jo.getBoolean("multiFactorAuthPresent"));
        
    }
    
    @Test
    /*
     * mfacode 五分半被用过一次
     */
    public void test_checkMFACode_mfaCodeused() throws Exception {
        String accountId="3fdmxmc3pqvmp";
        String userName=user1Name;
        String password=null;
        String mFACode1=getMFACode(base32StringSeed);
        
            
        String body=createLoginParam(accountId, userName, password, mFACode1);
        String url=internalDomain+"checkCode";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(true, jo.getBoolean("multiFactorAuthPresent"));
        
        
        Thread.sleep(70000);

        Pair<Integer, String> result2=internalRequest(url, body);
        assertEquals(403, result2.first().intValue());
//        JSONObject jo=new JSONObject(result.second());
//        assertEquals(400, jo.getInt("status"));
//        assertEquals("InvalidArgument", jo.get("code"));
//        assertEquals("Request body must not be empty.", jo.get("message"));

        
        
        
    }
    
    @Test
    /*
     * mfacode 模拟被disable
     */
    public void test_checkMFACode_MFAdisable() throws JSONException {
        
        
    }
    
    @Test
    public void test_getAccountSummary() throws Exception {
        CleanAndCreateUser();
        String accountId=accountId1;
        String userName=null;
        String password=null;
        String mFACode=null;
            
        String body=createLoginParam(accountId, userName, password, mFACode);
        String url=internalDomain+"getAccountSummary";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo= new JSONObject(result.second());
        assertEquals(accountId, jo.get("accountId"));
        assertEquals(1, jo.getInt("users"));
        assertEquals(0, jo.getInt("groups"));
        assertEquals(0, jo.getInt("policies"));
        assertEquals(0, jo.getInt("mFADevices"));
        assertEquals(0, jo.getInt("mFADevicesInUse"));
        assertEquals(0, jo.getInt("accountMFAEnabled"));
        assertEquals(1, jo.getInt("accountAccessKeysPresent"));
        assertEquals(500, jo.getInt("usersQuota"));
        assertEquals(30, jo.getInt("groupsQuota"));
        assertEquals(150, jo.getInt("policiesQuota"));
        assertEquals(10, jo.getInt("groupsPerUserQuota"));
        assertEquals(10, jo.getInt("attachedPoliciesPerUserQuota"));
        assertEquals(10, jo.getInt("attachedPoliciesPerGroupQuota"));
        assertEquals(2, jo.getInt("accessKeysPerUserQuota"));
        assertEquals(2, jo.getInt("accessKeysPerAccountQuota"));
        
    }
    
    @Test
    public void test_getAccountSummary_nullParam() throws JSONException {
        String url=internalDomain+"getAccountSummary";
        Pair<Integer, String> result=internalRequest(url, null);
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.get("code"));
        assertEquals("Request body must be vaild json object.", jo.get("message"));
    }
    
    @Test
    public void test_getAccountSummary_NoParam() throws JSONException {
        String url=internalDomain+"getAccountSummary";
        Pair<Integer, String> result=internalRequest(url, "{}");
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.get("code"));
        assertEquals("Request body must not be empty.", jo.get("message"));
    }
    
    @Test
    public void test_getAccountSummary_accountIdNotExist() throws JSONException {
        String accountId="3fdmxmc5pqvmp";
        String body=createLoginParam(accountId, null, null, null);
        String url=internalDomain+"getAccountSummary";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(404, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(404, jo.getInt("status"));
        assertEquals("NoSuchEntity", jo.get("code"));
        assertEquals("The account with id '"+accountId+"' cannot be found.", jo.get("message"));
    }
    
    @Test
    public void test_getAccountSummary_accountIdEmpty() throws JSONException {
        String accountId="";
        String body=createLoginParam(accountId, null, null, null);
        String url=internalDomain+"getAccountSummary";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.get("code"));
        assertEquals("AccountId must not be empty.", jo.get("message"));
    }
    
    @Test
    /*
     * 设置已用容量，查看返回
     */
    public void test_getAccountSummary_setUsed() throws Exception {
        CleanAndCreateUser();
        String accountId=accountId1;
        try {
            HConnection connection = HBaseConnectionManager.createConnection(GlobalHHZConfig.getConfig());
            HTableInterface htable =connection.getTable(IAMTestUtils.iamAccountSummaryTable);
            Put put = new Put(accountId.getBytes());
            put.add("i".getBytes(), "users".getBytes(), Bytes.toBytes(1L)); 
            put.add("i".getBytes(), "groups".getBytes(), Bytes.toBytes(2L)); 
            put.add("i".getBytes(), "policies".getBytes(), Bytes.toBytes(3L)); 
            put.add("i".getBytes(), "mFADevices".getBytes(), Bytes.toBytes(4L)); 
            put.add("i".getBytes(), "mFADevicesInUse".getBytes(), Bytes.toBytes(5L)); 
            put.add("i".getBytes(), "accountMFAEnabled".getBytes(), Bytes.toBytes(6L));
            
            HBaseUtil.put(htable, put);
            
            
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        String body=createLoginParam(accountId, null, null, null);
        String url=internalDomain+"getAccountSummary";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject jo= new JSONObject(result.second());
        assertEquals(accountId, jo.get("accountId"));
        assertEquals(1, jo.getInt("users"));
        assertEquals(2, jo.getInt("groups"));
        assertEquals(3, jo.getInt("policies"));
        assertEquals(4, jo.getInt("mFADevices"));
        assertEquals(5, jo.getInt("mFADevicesInUse"));
        assertEquals(6, jo.getInt("accountMFAEnabled"));
        assertEquals(1, jo.getInt("accountAccessKeysPresent"));
        assertEquals(500, jo.getInt("usersQuota"));
        assertEquals(30, jo.getInt("groupsQuota"));
        assertEquals(150, jo.getInt("policiesQuota"));
        assertEquals(10, jo.getInt("groupsPerUserQuota"));
        assertEquals(10, jo.getInt("attachedPoliciesPerUserQuota"));
        assertEquals(10, jo.getInt("attachedPoliciesPerGroupQuota"));
        assertEquals(2, jo.getInt("accessKeysPerUserQuota"));
        assertEquals(2, jo.getInt("accessKeysPerAccountQuota"));
        
    }
    
    @Test
    public void test_putAccountQuota() throws JSONException {
        String accountId=accountId1;
        JSONObject requestJsonObject=new JSONObject();
        requestJsonObject.put("accountId", accountId);
        requestJsonObject.put("usersQuota", 100);
        requestJsonObject.put("groupsQuota", 200);
        requestJsonObject.put("policiesQuota", 300);
        requestJsonObject.put("groupsPerUserQuota", 400);
        requestJsonObject.put("attachedPoliciesPerUserQuota", 500);
        requestJsonObject.put("attachedPoliciesPerGroupQuota", 600);
        requestJsonObject.put("accessKeysPerUserQuota", 700);
        requestJsonObject.put("accessKeysPerAccountQuota", 800);

        String body=requestJsonObject.toString();
        String url=internalDomain+"putAccountQuota";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject responseJsonObject= new JSONObject(result.second());
        assertEquals(accountId, responseJsonObject.get("accountId"));
        assertEquals(100, responseJsonObject.getInt("usersQuota"));
        assertEquals(200, responseJsonObject.getInt("groupsQuota"));
        assertEquals(300, responseJsonObject.getInt("policiesQuota"));
        assertEquals(400, responseJsonObject.getInt("groupsPerUserQuota"));
        assertEquals(500, responseJsonObject.getInt("attachedPoliciesPerUserQuota"));
        assertEquals(600, responseJsonObject.getInt("attachedPoliciesPerGroupQuota"));
        assertEquals(700, responseJsonObject.getInt("accessKeysPerUserQuota"));
        assertEquals(800, responseJsonObject.getInt("accessKeysPerAccountQuota"));   
    }
    
    @Test
    /*
     * 修改部分
     */
    public void test_putAccountQuota_PartParam() throws Exception {
        CleanAndCreateUser();
        String accountId=accountId1;
        
        String getbody=createLoginParam(accountId, null, null, null);
        String geturl=internalDomain+"getAccountSummary";
        Pair<Integer, String> getresult=internalRequest(geturl, getbody);
        assertEquals(200, getresult.first().intValue());
        
        String beforeString=getresult.second();
        
        JSONObject requestJsonObject=new JSONObject();
        requestJsonObject.put("accountId", accountId);
        requestJsonObject.put("usersQuota", 111);
        requestJsonObject.put("groupsQuota", 222);
        requestJsonObject.put("policiesQuota", 333);
        requestJsonObject.put("groupsPerUserQuota", 444);

        String body=requestJsonObject.toString();
        String url=internalDomain+"putAccountQuota";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject responseJsonObject= new JSONObject(result.second());
        assertEquals(accountId, responseJsonObject.get("accountId"));
        assertEquals(111, responseJsonObject.getInt("usersQuota"));
        assertEquals(222, responseJsonObject.getInt("groupsQuota"));
        assertEquals(333, responseJsonObject.getInt("policiesQuota"));
        assertEquals(444, responseJsonObject.getInt("groupsPerUserQuota"));
        
        Pair<Integer, String> getresult2=internalRequest(geturl, getbody);
        assertEquals(200, getresult2.first().intValue());
        
        String afterString=getresult2.second();
        
        JSONObject beforeJsonObject=new JSONObject(beforeString);
        JSONObject afterJsonObject=new JSONObject(afterString);
        assertEquals(accountId, beforeJsonObject.get("accountId"));
        assertEquals(beforeJsonObject.getInt("users"), afterJsonObject.getInt("users"));
        assertEquals(beforeJsonObject.getInt("groups"), afterJsonObject.getInt("groups"));
        assertEquals(beforeJsonObject.getInt("policies"), afterJsonObject.getInt("policies"));
        assertEquals(beforeJsonObject.getInt("mFADevices"), afterJsonObject.getInt("mFADevices"));
        assertEquals(beforeJsonObject.getInt("mFADevicesInUse"), afterJsonObject.getInt("mFADevicesInUse"));
        assertEquals(beforeJsonObject.getInt("accountMFAEnabled"), afterJsonObject.getInt("accountMFAEnabled"));
        assertEquals(beforeJsonObject.getInt("accountAccessKeysPresent"), afterJsonObject.getInt("accountAccessKeysPresent"));
        assertEquals(111, afterJsonObject.getInt("usersQuota"));
        assertEquals(222, afterJsonObject.getInt("groupsQuota"));
        assertEquals(333, afterJsonObject.getInt("policiesQuota"));
        assertEquals(444, afterJsonObject.getInt("groupsPerUserQuota"));
        assertEquals(beforeJsonObject.getInt("attachedPoliciesPerUserQuota"), afterJsonObject.getInt("attachedPoliciesPerUserQuota"));
        assertEquals(beforeJsonObject.getInt("attachedPoliciesPerGroupQuota"), afterJsonObject.getInt("attachedPoliciesPerGroupQuota"));
        assertEquals(beforeJsonObject.getInt("accessKeysPerUserQuota"), afterJsonObject.getInt("accessKeysPerUserQuota"));
        assertEquals(beforeJsonObject.getInt("accessKeysPerAccountQuota"), afterJsonObject.getInt("accessKeysPerAccountQuota"));
  
    }
    
    @Test
    /*
     * 没有设置可选参数
     */
    public void test_putAccountQuota_NoOption() throws JSONException {
        
        String accountId=accountId1;
  
        String getbody=createLoginParam(accountId, null, null, null);
        String geturl=internalDomain+"getAccountSummary";
        Pair<Integer, String> getresult=internalRequest(geturl, getbody);
        assertEquals(200, getresult.first().intValue());
        
        String beforeString=getresult.second();

        JSONObject requestJsonObject=new JSONObject();
        requestJsonObject.put("accountId", accountId);
        
        String body=requestJsonObject.toString();
        String url=internalDomain+"putAccountQuota";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject responseJsonObject= new JSONObject(result.second());
        assertEquals(accountId, responseJsonObject.get("accountId"));
        

        Pair<Integer, String> getresult2=internalRequest(geturl, getbody);
        assertEquals(200, getresult2.first().intValue());
        
        String afterString=getresult2.second();
        
        assertEquals(beforeString, afterString);
    }
    
    
    @Test
    /*
     * 设置参数有错误
     */
    public void test_putAccountQuota_errorParam() throws JSONException {
        String accountId=accountId1;
        
        String getbody=createLoginParam(accountId, null, null, null);
        String geturl=internalDomain+"getAccountSummary";
        Pair<Integer, String> getresult=internalRequest(geturl, getbody);
        assertEquals(200, getresult.first().intValue());
        
        String beforeString=getresult.second();

        JSONObject requestJsonObject=new JSONObject();
        requestJsonObject.put("accountId", accountId);
        requestJsonObject.put("userQuota", 22222);
        
        String body=requestJsonObject.toString();
        String url=internalDomain+"putAccountQuota";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject responseJsonObject= new JSONObject(result.second());
        assertEquals(accountId, responseJsonObject.get("accountId"));
        

        Pair<Integer, String> getresult2=internalRequest(geturl, getbody);
        assertEquals(200, getresult2.first().intValue());
        
        String afterString=getresult2.second();
        
        assertEquals(beforeString, afterString);
    }
    
    @Test
    /*
     * accountId 在数据库中不存在
     */
    public void test_putAccountQuota_AccountIdNotExist() throws JSONException {
        String accountId="3fdmxmc5pqvmp";
        JSONObject requestJsonObject=new JSONObject();
        requestJsonObject.put("accountId", accountId);
        requestJsonObject.put("usersQuota", 22222);
        
        String body=requestJsonObject.toString();
        String url=internalDomain+"putAccountQuota";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(404, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(404, jo.getInt("status"));
        assertEquals("NoSuchEntity", jo.get("code"));
        assertEquals("The account with id '"+accountId+"' cannot be found.", jo.get("message"));
        
    }
    
    @Test
    /*
     * accountId 在数据库中不存在
     */
    public void test_putAccountQuota_AccountIderror() throws JSONException {
        String accountId="3fdmxmc^&*";
        JSONObject requestJsonObject=new JSONObject();
        requestJsonObject.put("accountId", accountId);
        requestJsonObject.put("usersQuota", 22222);
        
        String body=requestJsonObject.toString();
        String url=internalDomain+"putAccountQuota";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.get("code"));
        assertEquals("The specified value for accountId is invalid.", jo.get("message"));
        
    }
    
    @Test
    /*
     * acountId 参数没有传
     */
    public void test_putAccountQuota_NoAccountId() throws JSONException {

        JSONObject requestJsonObject=new JSONObject();
        
        requestJsonObject.put("usersQuota", 22222);
        
        String body=requestJsonObject.toString();
        String url=internalDomain+"putAccountQuota";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.get("code"));
        assertEquals("AccountId must not be empty.", jo.get("message"));
    }
    
    @Test
    /*
     * acountId 参数为""
     */
    public void test_putAccountQuota_AccountIdEmpty() throws JSONException {
        JSONObject requestJsonObject=new JSONObject();
        requestJsonObject.put("accountId", "");
        requestJsonObject.put("usersQuota", 22222);
        
        String body=requestJsonObject.toString();
        String url=internalDomain+"putAccountQuota";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.get("code"));
        assertEquals("AccountId must not be empty.", jo.get("message"));
    }
    
    @Test
    /*
     * body为{}
     */
    public void test_putAccountQuota_paramEmpty() throws JSONException {
        String url=internalDomain+"putAccountQuota";
        Pair<Integer, String> result=internalRequest(url, "{}");
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.get("code"));
        assertEquals("Request body must not be empty.", jo.get("message"));
    }
    
    @Test
    /*
     * body为null
     */
    public void test_putAccountQuota_paramnull() throws JSONException {
        String url=internalDomain+"putAccountQuota";
        Pair<Integer, String> result=internalRequest(url, null);
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.get("code"));
        assertEquals("Request body must be vaild json object.", jo.get("message"));
    }
    
    
    @Test
    public void test_getSystemQuota() throws Exception {
        CleanAndCreateUser();
        String url=internalDomain+"getSystemQuota";
        Pair<Integer, String> result=internalRequest(url, null);
        assertEquals(200, result.first().intValue());
        JSONObject responseJsonObject= new JSONObject(result.second());
        assertEquals("systemQuota", responseJsonObject.get("accountId"));
        assertEquals(500, responseJsonObject.getInt("usersQuota"));
        assertEquals(30, responseJsonObject.getInt("groupsQuota"));
        assertEquals(150, responseJsonObject.getInt("policiesQuota"));
        assertEquals(10, responseJsonObject.getInt("groupsPerUserQuota"));
        assertEquals(10, responseJsonObject.getInt("attachedPoliciesPerUserQuota"));
        assertEquals(10, responseJsonObject.getInt("attachedPoliciesPerGroupQuota"));
        assertEquals(2, responseJsonObject.getInt("accessKeysPerUserQuota"));
        assertEquals(2, responseJsonObject.getInt("accessKeysPerAccountQuota"));   
    }
    
    @Test
    public void test_putSystemQuota() throws JSONException {
        JSONObject requestJsonObject=new JSONObject();
        requestJsonObject.put("accountId", "systemQuota");
        requestJsonObject.put("usersQuota", 10);
        requestJsonObject.put("groupsQuota", 20);
        requestJsonObject.put("policiesQuota", 30);
        requestJsonObject.put("groupsPerUserQuota", 40);
        requestJsonObject.put("attachedPoliciesPerUserQuota", 50);
        requestJsonObject.put("attachedPoliciesPerGroupQuota", 60);
        requestJsonObject.put("accessKeysPerUserQuota", 70);
        requestJsonObject.put("accessKeysPerAccountQuota", 80);

        String body=requestJsonObject.toString();
        String url=internalDomain+"putSystemQuota";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject responseJsonObject= new JSONObject(result.second());
        assertEquals("systemQuota", responseJsonObject.get("accountId"));
        assertEquals(10, responseJsonObject.getInt("usersQuota"));
        assertEquals(20, responseJsonObject.getInt("groupsQuota"));
        assertEquals(30, responseJsonObject.getInt("policiesQuota"));
        assertEquals(40, responseJsonObject.getInt("groupsPerUserQuota"));
        assertEquals(50, responseJsonObject.getInt("attachedPoliciesPerUserQuota"));
        assertEquals(60, responseJsonObject.getInt("attachedPoliciesPerGroupQuota"));
        assertEquals(70, responseJsonObject.getInt("accessKeysPerUserQuota"));
        assertEquals(80, responseJsonObject.getInt("accessKeysPerAccountQuota"));   
    }
    
    @Test
    /*
     * 修改一部分
     */
    public void test_putSystemQuota_PartParam() throws JSONException {
        String geturl=internalDomain+"getSystemQuota";
        Pair<Integer, String> getresult=internalRequest(geturl, null);
        assertEquals(200, getresult.first().intValue());
        String before=getresult.second();
        
        JSONObject requestJsonObject=new JSONObject();
        requestJsonObject.put("accountId", "systemQuota");
        requestJsonObject.put("attachedPoliciesPerUserQuota", 55);
        requestJsonObject.put("attachedPoliciesPerGroupQuota", 66);
        requestJsonObject.put("accessKeysPerUserQuota", 77);
        requestJsonObject.put("accessKeysPerAccountQuota", 88);

        String body=requestJsonObject.toString();
        String url=internalDomain+"putSystemQuota";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject responseJsonObject= new JSONObject(result.second());
        assertEquals("systemQuota", responseJsonObject.get("accountId"));;
        assertEquals(55, responseJsonObject.getInt("attachedPoliciesPerUserQuota"));
        assertEquals(66, responseJsonObject.getInt("attachedPoliciesPerGroupQuota"));
        assertEquals(77, responseJsonObject.getInt("accessKeysPerUserQuota"));
        assertEquals(88, responseJsonObject.getInt("accessKeysPerAccountQuota"));   
        
        Pair<Integer, String> getresult2=internalRequest(geturl, null);
        assertEquals(200, getresult2.first().intValue());
        String after=getresult2.second();
        
        JSONObject beforeJsonObject=new JSONObject(before);
        JSONObject afterJsonObject=new JSONObject(after);
        
        assertEquals("systemQuota", afterJsonObject.get("accountId"));
        assertEquals(beforeJsonObject.getInt("usersQuota"), afterJsonObject.getInt("usersQuota"));
        assertEquals(beforeJsonObject.getInt("groupsQuota"), afterJsonObject.getInt("groupsQuota"));
        assertEquals(beforeJsonObject.getInt("policiesQuota"), afterJsonObject.getInt("policiesQuota"));
        assertEquals(beforeJsonObject.getInt("groupsPerUserQuota"), afterJsonObject.getInt("groupsPerUserQuota"));
        assertEquals(55, afterJsonObject.getInt("attachedPoliciesPerUserQuota"));
        assertEquals(66, afterJsonObject.getInt("attachedPoliciesPerGroupQuota"));
        assertEquals(77, afterJsonObject.getInt("accessKeysPerUserQuota"));
        assertEquals(88, afterJsonObject.getInt("accessKeysPerAccountQuota"));   
        
    }
    
    @Test
    /*
     * accountId 不存在
     */
    public void test_putSystemQuota_NoAcccountId() throws JSONException {
        JSONObject requestJsonObject=new JSONObject();
        requestJsonObject.put("usersQuota", 11);
        requestJsonObject.put("groupsQuota", 21);
        requestJsonObject.put("policiesQuota", 31);
        requestJsonObject.put("groupsPerUserQuota", 41);
        requestJsonObject.put("attachedPoliciesPerUserQuota", 51);
        requestJsonObject.put("attachedPoliciesPerGroupQuota", 61);
        requestJsonObject.put("accessKeysPerUserQuota", 71);
        requestJsonObject.put("accessKeysPerAccountQuota", 81);

        String body=requestJsonObject.toString();
        String url=internalDomain+"putSystemQuota";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject responseJsonObject= new JSONObject(result.second());
        assertEquals("systemQuota", responseJsonObject.get("accountId"));
        assertEquals(11, responseJsonObject.getInt("usersQuota"));
        assertEquals(21, responseJsonObject.getInt("groupsQuota"));
        assertEquals(31, responseJsonObject.getInt("policiesQuota"));
        assertEquals(41, responseJsonObject.getInt("groupsPerUserQuota"));
        assertEquals(51, responseJsonObject.getInt("attachedPoliciesPerUserQuota"));
        assertEquals(61, responseJsonObject.getInt("attachedPoliciesPerGroupQuota"));
        assertEquals(71, responseJsonObject.getInt("accessKeysPerUserQuota"));
        assertEquals(81, responseJsonObject.getInt("accessKeysPerAccountQuota"));   
    }
    
    @Test
    /*
     * accountId 不是systemQuota
     */
    public void test_putSystemQuota_AccountIdNotsystemQuota() throws JSONException {
        JSONObject requestJsonObject=new JSONObject();
        requestJsonObject.put("accountId", accountId1);
        requestJsonObject.put("usersQuota", 12);
        requestJsonObject.put("groupsQuota", 22);
        requestJsonObject.put("policiesQuota", 32);
        requestJsonObject.put("groupsPerUserQuota", 42);
        requestJsonObject.put("attachedPoliciesPerUserQuota", 52);
        requestJsonObject.put("attachedPoliciesPerGroupQuota", 62);
        requestJsonObject.put("accessKeysPerUserQuota", 72);
        requestJsonObject.put("accessKeysPerAccountQuota", 82);

        String body=requestJsonObject.toString();
        String url=internalDomain+"putSystemQuota";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject responseJsonObject= new JSONObject(result.second());
        assertEquals("systemQuota", responseJsonObject.get("accountId"));
        assertEquals(12, responseJsonObject.getInt("usersQuota"));
        assertEquals(22, responseJsonObject.getInt("groupsQuota"));
        assertEquals(32, responseJsonObject.getInt("policiesQuota"));
        assertEquals(42, responseJsonObject.getInt("groupsPerUserQuota"));
        assertEquals(52, responseJsonObject.getInt("attachedPoliciesPerUserQuota"));
        assertEquals(62, responseJsonObject.getInt("attachedPoliciesPerGroupQuota"));
        assertEquals(72, responseJsonObject.getInt("accessKeysPerUserQuota"));
        assertEquals(82, responseJsonObject.getInt("accessKeysPerAccountQuota"));   
    }
    
    @Test
    /*
     * 设置参数有错误
     */
    public void test_putSystemQuota_errorParam() throws JSONException {
        String geturl=internalDomain+"getSystemQuota";
        Pair<Integer, String> getresult=internalRequest(geturl, null);
        assertEquals(200, getresult.first().intValue());
        String before=getresult.second();
        
        JSONObject requestJsonObject=new JSONObject();
        requestJsonObject.put("groupQuota", 22222);


        String body=requestJsonObject.toString();
        String url=internalDomain+"putSystemQuota";
        Pair<Integer, String> result=internalRequest(url, body);
        assertEquals(200, result.first().intValue());
        JSONObject responseJsonObject= new JSONObject(result.second());
        assertEquals("systemQuota", responseJsonObject.get("accountId"));

//        assertEquals(21, responseJsonObject.getInt("groupsQuota")); 
        
        Pair<Integer, String> getresult2=internalRequest(geturl, null);
        assertEquals(200, getresult2.first().intValue());
        String after=getresult2.second();
        
        assertEquals(before, after);
    }
    
    @Test
    /*
     * body为{}
     */
    public void test_putSystemQuota_paramEmpty() throws JSONException {
        String url=internalDomain+"putSystemQuota";
        Pair<Integer, String> result=internalRequest(url, "{}");
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.get("code"));
        assertEquals("Request body must not be empty.", jo.get("message"));
    }
    
    @Test
    /*
     * 设置参数有错误
     */
    public void test_putSystemQuota_paramnull() throws JSONException {
        String url=internalDomain+"putSystemQuota";
        Pair<Integer, String> result=internalRequest(url, null);
        assertEquals(400, result.first().intValue());
        JSONObject jo=new JSONObject(result.second());
        assertEquals(400, jo.getInt("status"));
        assertEquals("InvalidArgument", jo.get("code"));
        assertEquals("Request body must be vaild json object.", jo.get("message"));
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
    
    public String  createLoginParam(String accountId,String userName,String password,String mFACode) {
        JSONObject jObject= new JSONObject();
        try {
            if (accountId!=null) {
                jObject.put("accountId", accountId);
            }
            if (userName!=null) {
                jObject.put("userName", userName);
            }
            if (password!=null) {
                jObject.put("password", password);
            }
            if (mFACode!=null) {
                jObject.put("mFACode", mFACode);
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return jObject.toString();
    }
    
    
    public Pair<String, String> CreateIdentifyingCode(String secret) {
        Pair<String, String> codePair = new Pair<String, String>();
        int WINDOW_SIZE = 3;
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);
        long t = System.currentTimeMillis() / 1000L / 30L;
        
        String code1="";
        String code2="";
        
        for (int i = -WINDOW_SIZE; i <= WINDOW_SIZE; ++i) {
            long hash1 = generateCode(decodedKey, t + i);
            long hash2 = generateCode(decodedKey, t + i + 1);
            
            code1=String.valueOf(hash1);
            code2=String.valueOf(hash2);
        }
        
     // 不够6位前面补0
        if (code1.length()<6) {
            int b0=6-code1.length();
            String prefix="";
            for (int i = 0; i < b0; i++) {
                prefix+="0";
            }
            code1=prefix+code1;
        }
        
        if (code2.length()<6) {
            int b0=6-code2.length();
            String prefix="";
            for (int i = 0; i < b0; i++) {
                prefix+="0";
            }
            code2=prefix+code2;
        }
        
        codePair.first(code1);
        codePair.second(code2);
        return codePair;
    }
    
    public static String getMFACode(String secret) {
        int WINDOW_SIZE = 3;
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);
        long t = System.currentTimeMillis() / 1000L / 30L;
        
        String mfaCode="";
        for (int i = -WINDOW_SIZE; i <= WINDOW_SIZE; ++i) {
            long hash1 = generateCode(decodedKey, t + i);
            mfaCode=String.valueOf(hash1);
        }
       
        // 不够6位前面补0
        if (mfaCode.length()<6) {
            int b0=6-mfaCode.length();
            String prefix="";
            for (int i = 0; i < b0; i++) {
                prefix+="0";
            }
            mfaCode=prefix+mfaCode;
        }
        
        return mfaCode;
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
    
    public Pair<String, String> AssertcreateVirtualMFADevice(String xml,String serialNumber) {
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
            // TODO: handle exception
        }
        
        return null;
    }

}
