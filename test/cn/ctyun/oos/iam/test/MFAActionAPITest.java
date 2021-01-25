package cn.ctyun.oos.iam.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.io.IOUtils;
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
import cn.ctyun.oos.iam.server.action.api.UserAction;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.internal.api.IAMInternalAPI;
import cn.ctyun.oos.iam.server.internal.api.LoginParam;
import cn.ctyun.oos.iam.server.internal.api.LoginResult;
import cn.ctyun.oos.iam.server.param.CreateUserParam;
import cn.ctyun.oos.iam.signer.Misc;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class MFAActionAPITest {
	public static final String OOS_IAM_DOMAIN="https://oos-cd-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName="cd";
	
	private static String ownerName = "root_user@test.com";
	public static final String accessKey="userak";
	public static final String secretKey="usersk";
	
	public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);
		
		AkSkMeta aksk=new AkSkMeta(owner.getId());
        aksk.accessKey=accessKey;
        aksk.setSecretKey(secretKey);
        aksk.isPrimary=1;
        metaClient.akskInsert(aksk);
        
        // 创建第一个子用户
     	CreateUserParam param=new CreateUserParam();
     	param.userName="test_subuser1";
     	metaClient.ownerSelect(owner);
     	param.currentOwner=owner;
     	param.currentAccessKey=new AkSkMeta(owner.getId());
     		
     	UserAction.createUser(param);
     		
     	// 创建第二个子用户
     	CreateUserParam param2=new CreateUserParam();
     	param2.userName="test_subuser2";
     	metaClient.ownerSelect(owner);
     	param2.currentOwner=owner;
     	param2.currentAccessKey=new AkSkMeta(owner.getId());
     				
     	UserAction.createUser(param2);
	}

	@Before
	public void setUp() throws Exception {
		IAMTestUtils.TrancateTable(IAMTestUtils.iammfaDeviceTable);
		
	}
	

	@Test
	/*
	 * 创建设备
	 */
	public void test_createVirtualMFADevice() throws Exception{

        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
	}
	
	@Test
	/*
	 * 创建同名设备
	 */
	public void test_createVirtualMFADevice_SameName() throws Exception{
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");

        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409, resultPair2.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair2.second());
		assertEquals("EntityAlreadyExists", error.get("Code"));
		assertEquals("MFADevice entity at the same path and name already exists.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
    /*
     * 创建同名设备，大小写不一致
     */
    public void test_createVirtualMFADevice_SameName2() throws Exception{
        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");

        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=Mfa1";
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(409, resultPair2.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair2.second());
        assertEquals("EntityAlreadyExists", error.get("Code"));
        assertEquals("MFADevice entity at the same path and name already exists.", error.get("Message"));
        assertEquals("/", error.get("Resource"));
    }
	
	@Test
	/*
	 * 创建设备超过上限
	 */
	public void test_createVirtualMFADevice_MoreThan() throws Exception{
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa2";
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair2.first().intValue());
        AssertcreateVirtualMFADevice(resultPair2.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa3";
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair3.first().intValue());
        AssertcreateVirtualMFADevice(resultPair3.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa3");

        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa4";
        Pair<Integer, String> resultPair4=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409, resultPair4.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair4.second());
		assertEquals("LimitExceeded", error.get("Code"));
		assertEquals("Cannot exceed quota for MFADevices: 3.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	

	@Test
	/*
	 * 创建设备时VirtualMFADeviceName内容为空
	 */
	public void test_createVirtualMFADevice_NoDeviceName() throws Exception{

        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'virtualMFADeviceName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-", error.get("Message"));
		assertEquals("/", error.get("Resource"));
        
	}
	
	@Test
	/*
	 * 创建设备时不携带VirtualMFADeviceName
	 */
	public void test_createVirtualMFADevice_NoDeviceNameParam() throws Exception{

        String body="Action=CreateVirtualMFADevice";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'virtualMFADeviceName' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("/", error.get("Resource"));
        
	}
	
	@Test
	/*
	 * 创建设备,设备名为1位
	 */
	public void test_createVirtualMFADevice_VirtualMFADeviceNameParam_1Charater() throws Exception{

        String VirtualMFADeviceName="1";
        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName="+VirtualMFADeviceName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/1");
        
	}
	
	@Test
	/*
	 * 创建设备,设备名包含空格
	 */
	public void test_createVirtualMFADevice_VirtualMFADeviceNameParam_blank() throws Exception{
        String VirtualMFADeviceName="abc 123";
        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName="+VirtualMFADeviceName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'virtualMFADeviceName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-", error.get("Message"));
		assertEquals("/", error.get("Resource"));
        
	}
	
	@Test
	/*
	 * 创建设备,设备名包含特殊字符：_ + =，.@ -(包含_@.)
	 * 
	 */
	public void test_createVirtualMFADevice_VirtualMFADeviceNameParam_specialCharater1() throws Exception{
        
        String VirtualMFADeviceName="yan_xiao1111@163.com";
        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName="+VirtualMFADeviceName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/yan_xiao1111@163.com");
	
	}
	
	
	@Test
	/*
	 * 创建设备,设备名包含特殊字符：_ + =，.@ -(包含=)
	 * 
	 */
	public void test_createVirtualMFADevice_VirtualMFADeviceNameParam_specialCharater2() throws Exception{

        String VirtualMFADeviceName="username=abc,121-2";
        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName="+UrlEncoded.encodeString(VirtualMFADeviceName);
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/"+VirtualMFADeviceName);
 
	}
	
	@Test
	/*
	 * 创建设备,设备名包含特殊字符：_ + =，.@ -(包含,-)
	 * 
	 */
	public void test_createVirtualMFADevice_VirtualMFADeviceNameParam_specialCharater3() throws Exception{
        
        String VirtualMFADeviceName="username=abc,12-1";
        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName="+UrlEncoded.encodeString(VirtualMFADeviceName);
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/"+VirtualMFADeviceName);
 
	}
	
	@Test
	/*
	 * 创建设备,设备名为128位
	 */
	public void test_createVirtualMFADevice_VirtualMFADeviceNameParam_128Charater() throws Exception{
		
        String VirtualMFADeviceName="abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx";
        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName="+VirtualMFADeviceName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/"+VirtualMFADeviceName);  
	}
	
	@Test
	/*
	 * 创建设备,设备名为129位
	 */
	public void test_createVirtualMFADevice_VirtualMFADeviceNameParam_129Charater() throws Exception{
		
        String VirtualMFADeviceName="abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxy";
        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName="+VirtualMFADeviceName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value \'"+VirtualMFADeviceName+"\' at 'virtualMFADeviceName' failed to satisfy constraint: Member must have length less than or equal to 128", error.get("Message"));
		assertEquals("/", error.get("Resource"));
        
	}
	
	@Test
	/*
	 * 给用户绑定设备
	 */
	public void test_enableMFADevice() throws Exception{
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
	}
	
	@Test
	/*
	 * 给用户绑定设备，绑定设备已经绑定同一个用户
	 */
	public void test_enableMFADevice_alreadbyself() throws Exception{
		
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(409, resultPair3.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair3.second());
		assertEquals("EntityAlreadyExists", error.get("Code"));
		assertEquals("MFA Device is already in use.", error.get("Message"));
		assertEquals("test_subuser1", error.get("Resource"));
	}
	
	@Test
	/*
	 * 给用户绑定设备，绑定设备已经绑定不同一个用户
	 */
	public void test_enableMFADevice_alreadbyOther() throws Exception{
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser2&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(409, resultPair3.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair3.second());
		assertEquals("EntityAlreadyExists", error.get("Code"));
		assertEquals("MFA Device is already in use.", error.get("Message"));
		assertEquals("test_subuser2", error.get("Resource"));

	}
	
	@Test
	public void test_enableMFADevice_oneUserEnableTwo() throws JSONException {
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa2";
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair3.first().intValue());
        Pair<String, String> devicePair2=AssertcreateVirtualMFADevice(resultPair3.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
        
        String SerialNumber2=devicePair2.first();
        String base32StringSeed2=devicePair2.second();
        Pair<String, String> codesPair2=CreateIdentifyingCode(base32StringSeed2);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber2)+"&AuthenticationCode1="+codesPair2.first()+"&AuthenticationCode2="+codesPair2.second();
        Pair<Integer, String> resultPair4=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(409, resultPair4.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair4.second());
		assertEquals("LimitExceeded", error.get("Code"));
		assertEquals("Cannot exceed quota limit for MFADevicesPerUser.", error.get("Message"));
		assertEquals("test_subuser1", error.get("Resource"));
	}
	
	@Test
	/*
	 * 绑定用户时携带UserName的值在数据库不存在该用户
	 */
	public void test_enableMFADevice_UserNotExist() throws Exception{
		
		String username="nouser";
        String SerialNumber="arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1";
        String base32StringSeed="X7QSF6FIDOKUCXMHKSGLV334YOUCDSKFXYEDA7IQHJSRSDRQFM3RTAM2T7LLZDLK";
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        String body="Action=EnableMFADevice&Version=2010-05-08&UserName=nouser&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(404, resultPair.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name "+username+" cannot be found.", error.get("Message"));
		assertEquals(username, error.get("Resource"));
        
	}
	
	@Test
	/*
	 * 绑定用户时携带不携带UserName参数
	 */
	public void test_enableMFADevice_NoUserNameParam() throws Exception{
        
        String SerialNumber="arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1";
        String base32StringSeed="X7QSF6FIDOKUCXMHKSGLV334YOUCDSKFXYEDA7IQHJSRSDRQFM3RTAM2T7LLZDLK";
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        String body="Action=EnableMFADevice&Version=2010-05-08&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, resultPair.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("", error.get("Resource"));
        
	}
	
	@Test
	/*
	 * 绑定用户时携带SerialNumber的值在数据库不存
	 */
	public void test_enableMFADevice_SerialNumberNotExist() throws Exception{
		
        String SerialNumber="arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1";
        String base32StringSeed="A7QSF6FIDOKUCXMHKSGLV334YOUCDSKFXYEDA7IQHJSRSDRQFM3RTAM2T7LLZDLK";
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        String body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(404, resultPair.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("VirtualMFADevice with serial number "+SerialNumber+" does not exist.", error.get("Message"));
		assertEquals("test_subuser1", error.get("Resource"));
        
	}
	
	@Test
	/*
	 * 绑定用户时携带SerialNumber的值不合法
	 */
	public void test_enableMFADevice_SerialNumberError() throws Exception{
		
		String deviceName="ab c";
		
        String SerialNumber="arn:ctyun:iam::3rmoqzn03g6ga:mfa/"+deviceName;
        String base32StringSeed="A7QSF6FIDOKUCXMHKSGLV334YOUCDSKFXYEDA7IQHJSRSDRQFM3RTAM2T7LLZDLK";
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        String body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, resultPair.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'serialNumber' is invalid", error.get("Message"));
		assertEquals("test_subuser1", error.get("Resource"));
        
	}
	
	@Test
	/*
	 * 绑定用户时携带不携带SerialNumber参数
	 */
	public void test_enableMFADevice_NoSerialNumberParam() throws Exception{
		
        String base32StringSeed="X7QSF6FIDOKUCXMHKSGLV334YOUCDSKFXYEDA7IQHJSRSDRQFM3RTAM2T7LLZDLK";
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        String body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, resultPair.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'serialNumber' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("test_subuser1", error.get("Resource"));
        
	}
	
	@Test
	/*
	 * 
	 * 绑定用户时携带AuthenticationCode1的值为非算法得出
	 */
	public void test_enableMFADevice_AuthenticationCode1_Error() throws Exception{
		
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1=123456"+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(403, resultPair2.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair2.second());
		assertEquals("InvalidAuthenticationCode", error.get("Code"));
		assertEquals("Authentication code for device is not valid.", error.get("Message"));
		assertEquals("test_subuser1", error.get("Resource"));
        
	}
	
	@Test
	/*
	 * 绑定用户时不携带AuthenticationCode1参数
	 */
	public void test_enableMFADevice_NoAuthenticationCode1Param() throws Exception{
		
        String SerialNumber="arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1";
        String base32StringSeed="X7QSF6FIDOKUCXMHKSGLV334YOUCDSKFXYEDA7IQHJSRSDRQFM3RTAM2T7LLZDLK";
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        String body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, resultPair2.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair2.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'authenticationCode1' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("test_subuser1", error.get("Resource"));
	}
	
	@Test
	/*
	 * 绑定用户时携带AuthenticationCode1参数位数不是6位
	 */
	public void test_enableMFADevice_AuthenticationCode1Not6() throws JSONException {
		String SerialNumber="arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1";
        String base32StringSeed="X7QSF6FIDOKUCXMHKSGLV334YOUCDSKFXYEDA7IQHJSRSDRQFM3RTAM2T7LLZDLK";
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        String body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1=1234"+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, resultPair2.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair2.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'authenticationCode1' is invalid. It must be a six-digit decimal number", error.get("Message"));
		assertEquals("test_subuser1", error.get("Resource"));
	}
	
	@Test
	/*
	 * 
	 * 绑定用户时携带AuthenticationCode2的值为非算法得出
	 */
	public void test_enableMFADevice_AuthenticationCode2_error() throws Exception{
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2=123456";
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(403, resultPair2.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair2.second());
		assertEquals("InvalidAuthenticationCode", error.get("Code"));
		assertEquals("Authentication code for device is not valid.", error.get("Message"));
		assertEquals("test_subuser1", error.get("Resource"));
	}
	
	@Test
	/*
	 * 绑定用户时携带不携带AuthenticationCode2参数
	 */
	public void test_enableMFADevice_NoAuthenticationCode2Param() throws Exception{
		
        String SerialNumber="arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1";
        String base32StringSeed="X7QSF6FIDOKUCXMHKSGLV334YOUCDSKFXYEDA7IQHJSRSDRQFM3RTAM2T7LLZDLK";
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        String body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, resultPair2.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair2.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'authenticationCode2' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("test_subuser1", error.get("Resource"));
	}
	
	@Test
	/*
	 * 绑定用户时携带AuthenticationCode2参数位数不是6位
	 */
	public void test_enableMFADevice_AuthenticationCode2Not6() throws JSONException {
		String SerialNumber="arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1";
        String base32StringSeed="X7QSF6FIDOKUCXMHKSGLV334YOUCDSKFXYEDA7IQHJSRSDRQFM3RTAM2T7LLZDLK";
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        String body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2=1234";
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, resultPair2.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair2.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'authenticationCode2' is invalid. It must be a six-digit decimal number", error.get("Message"));
		assertEquals("test_subuser1", error.get("Resource"));
	}
	
	@Test
	/*
	 * 设备和用户解绑
	 */
	public void test_deactivateMFADevice() throws Exception{
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        body="Action=DeactivateMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber);
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair3.first().intValue());
        
	}
	
	@Test
	/*
	 * 解绑没有绑定设备的用户
	 */
	public void test_deactivateMFADevice_NoEnableMFADevice() throws Exception{
		
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());

        body="Action=DeactivateMFADevice&Version=2010-05-08&UserName=test_subuser2&SerialNumber="+UrlEncoded.encodeString(SerialNumber);
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(404, resultPair3.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair3.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("MFA Device invalid for user.", error.get("Message"));
		assertEquals("test_subuser2", error.get("Resource"));
	}
	
	@Test
	/*
	 * 设备和用户解绑UserName的值用户在数据库不存在
	 */
	public void test_deactivateMFADevice_NoUser() throws Exception{
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());

        body="Action=DeactivateMFADevice&Version=2010-05-08&UserName=nouser&SerialNumber="+UrlEncoded.encodeString(SerialNumber);
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(404, resultPair3.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair3.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name nouser cannot be found.", error.get("Message"));
		assertEquals("nouser", error.get("Resource"));
	}
	
	@Test
	/*
	 * 设备和用户解绑时不携带UserName
	 */
	public void test_deactivateMFADevice_NoUserNameParam() throws Exception{
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());

        body="Action=DeactivateMFADevice&Version=2010-05-08&SerialNumber="+UrlEncoded.encodeString(SerialNumber);
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, resultPair3.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair3.second());
        assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * 设备和用户解绑SerialNumber的值在数据库不存在
	 */
	public void test_deactivateMFADevice_NoSerialNumberExist() throws Exception{
		
        String SerialNumber="arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1111111";
        String body="Action=DeactivateMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber);
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(404, resultPair3.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair3.second());
        assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("VirtualMFADevice with serial number "+SerialNumber+" does not exist.", error.get("Message"));
		assertEquals("test_subuser1", error.get("Resource"));
        
	}
	
	@Test
	/*
	 * 设备和用户解绑时不携带SerialNumber
	 */
	public void test_deactivateMFADevice_NoSerialNumberParam() throws Exception{

        String body="Action=DeactivateMFADevice&Version=2010-05-08&UserName=test_subuser1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
        assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'serialNumber' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("test_subuser1", error.get("Resource"));
	}
	
	@Test
	/*
	 * list 设备，不加AssignmentStatus参数
	 */
	public void test_listVirtualMFADevices() throws Exception{
	    String body="Action=CreateLoginProfile&UserName=test_subuser1&Password=a12345678";
        Pair<Integer, String> setPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, setPasswd.first().intValue());
	    
	    LoginParam loginParam = new LoginParam();
        loginParam.accountId = "3rmoqzn03g6ga";
        loginParam.userName = "test_subuser1";
        loginParam.passwordMd5 = Misc.getMd5("a12345678");
        loginParam.loginIp="192.168.1.1";
        
        LoginResult loginResult = IAMInternalAPI.login(loginParam);

		body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa2";
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair3.first().intValue());
        AssertcreateVirtualMFADevice(resultPair3.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
        
        
        body="Action=ListVirtualMFADevices&Version=2010-05-08";
        Pair<Integer, String> resultPair4=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair4.first().intValue());
        
		List<Pair<String, String>> devices= new ArrayList<Pair<String,String>>();
		Pair<String, String> device1=new Pair<String, String>();
		device1.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
		device1.second("test_subuser1");
		Pair<String, String> device2=new Pair<String, String>();
		device2.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
		devices.add(device1);
		devices.add(device2);
		AssertListVirtualMFADevicesResult(resultPair4.second(), devices, false);
	}
	
	@Test
    /*
     * list 设备，不加AssignmentStatus参数
     */
    public void test_listVirtualMFADevices2() throws Exception{

        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        
        body="Action=CreateLoginProfile&UserName=test_subuser1&Password=a12345678";
        Pair<Integer, String> setPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, setPasswd.first().intValue());
        LoginParam loginParam = new LoginParam();
        loginParam.accountId = "3rmoqzn03g6ga";
        loginParam.userName = "test_subuser1";
        loginParam.passwordMd5 = Misc.getMd5("a12345678");
        
        LoginResult loginResult = IAMInternalAPI.login(loginParam);
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa2";
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair3.first().intValue());
        AssertcreateVirtualMFADevice(resultPair3.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
        
        
        body="Action=ListVirtualMFADevices&Version=2010-05-08";
        Pair<Integer, String> resultPair4=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair4.first().intValue());
        
        List<Pair<String, String>> devices= new ArrayList<Pair<String,String>>();
        Pair<String, String> device1=new Pair<String, String>();
        device1.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        device1.second("test_subuser1");
        Pair<String, String> device2=new Pair<String, String>();
        device2.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
        devices.add(device1);
        devices.add(device2);
        AssertListVirtualMFADevicesResult(resultPair4.second(), devices, false);
    }
	
	@Test
	/*
	 * list 设备，不加AssignmentStatus参数分页查询
	 */
	public void test_listVirtualMFADevices_MaxItems2() throws Exception{

		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		 Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa2";
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair2.first().intValue());
        AssertcreateVirtualMFADevice(resultPair2.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa3";
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair3.first().intValue());
        AssertcreateVirtualMFADevice(resultPair3.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa3");

        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair4=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair4.first().intValue());
        
        
        body="Action=ListVirtualMFADevices&Version=2010-05-08&MaxItems=2";
        Pair<Integer, String> resultPair5=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair5.first().intValue());
		
		List<Pair<String, String>> devices= new ArrayList<Pair<String,String>>();
		Pair<String, String> device1=new Pair<String, String>();
		device1.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
		device1.second("test_subuser1");
		Pair<String, String> device2=new Pair<String, String>();
		device2.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
		devices.add(device1);
		devices.add(device2);
		
		String marker=AssertListVirtualMFADevicesResult(resultPair5.second(), devices, true);
		body="Action=ListVirtualMFADevices&Version=2010-05-08&MaxItems=2&Marker="+marker;
	    Pair<Integer, String> resultPair6=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair6.first().intValue());
		List<Pair<String, String>> devices2= new ArrayList<Pair<String,String>>();
		Pair<String, String> device3=new Pair<String, String>();
		device3.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa3");
		devices2.add(device3);
		AssertListVirtualMFADevicesResult(resultPair6.second(), devices2, false);
	}
	
	@Test
	/*
	 * list 设备，AssignmentStatus参数为Any
	 */
	public void test_listVirtualMFADevices_Any() throws Exception{

		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa2";
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair3.first().intValue());
        AssertcreateVirtualMFADevice(resultPair3.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
        
        
        body="Action=ListVirtualMFADevices&Version=2010-05-08&AssignmentStatus=Any";
        Pair<Integer, String> resultPair4=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair4.first().intValue());
		
		List<Pair<String, String>> devices= new ArrayList<Pair<String,String>>();
		Pair<String, String> device1=new Pair<String, String>();
		device1.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
		device1.second("test_subuser1");
		Pair<String, String> device2=new Pair<String, String>();
		device2.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
		devices.add(device1);
		devices.add(device2);
		AssertListVirtualMFADevicesResult(resultPair4.second(), devices, false);
	}
	
	@Test
	/*
	 * list 设备，AssignmentStatus参数为Assigned
	 */
	public void test_listVirtualMFADevices_Assigned() throws Exception{

		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa2";
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair3.first().intValue());
        AssertcreateVirtualMFADevice(resultPair3.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
        
        
        body="Action=ListVirtualMFADevices&Version=2010-05-08&AssignmentStatus=Assigned";
        Pair<Integer, String> resultPair4=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair4.first().intValue());
		
		List<Pair<String, String>> devices= new ArrayList<Pair<String,String>>();
		Pair<String, String> device1=new Pair<String, String>();
		device1.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
		device1.second("test_subuser1");
		devices.add(device1);

		AssertListVirtualMFADevicesResult(resultPair4.second(), devices, false);
        
	}
	
	@Test
	/*
	 * list 设备，AssignmentStatus参数为Unassigned
	 */
	public void test_listVirtualMFADevices_Unassigned() throws Exception{

		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa2";
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair3.first().intValue());
        AssertcreateVirtualMFADevice(resultPair3.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
        
        
        body="Action=ListVirtualMFADevices&Version=2010-05-08&AssignmentStatus=Unassigned";
        Pair<Integer, String> resultPair4=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair4.first().intValue());
        
		List<Pair<String, String>> devices= new ArrayList<Pair<String,String>>();
		Pair<String, String> device2=new Pair<String, String>();
		device2.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
		devices.add(device2);
		AssertListVirtualMFADevicesResult(resultPair4.second(), devices, false);
	}
	
	@Test
	/*
	 * AssignmentStatus的值非 Assigned | Unassigned | Any
	 */
	public void test_listVirtualMFADevices_AssignmentStatusError() throws JSONException {
		String body="Action=ListVirtualMFADevices&Version=2010-05-08&AssignmentStatus=11111";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '11111' at 'assignmentStatus' failed to satisfy constraint: Member must satisfy enum value set: [Unassigned, Any, Assigned]", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	/*
	 * list 设备，AssignmentStatus参数为Assigned分页查询
	 */
	public void test_listVirtualMFADevices_Assigned_maxItmes1() throws Exception{

		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa2";
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair3.first().intValue());
		Pair<String, String> devicePair2=AssertcreateVirtualMFADevice(resultPair3.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
        
        String SerialNumber2=devicePair2.first();
        String base32StringSeed2=devicePair2.second();
        Pair<String, String> codesPair2=CreateIdentifyingCode(base32StringSeed2);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser2&SerialNumber="+UrlEncoded.encodeString(SerialNumber2)+"&AuthenticationCode1="+codesPair2.first()+"&AuthenticationCode2="+codesPair2.second();
        Pair<Integer, String> resultPair4=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair4.first().intValue());
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa3";
        Pair<Integer, String> resultPair5=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair5.first().intValue());
        AssertcreateVirtualMFADevice(resultPair5.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa3");
        
        
        body="Action=ListVirtualMFADevices&Version=2010-05-08&AssignmentStatus=Assigned&MaxItems=1";
        Pair<Integer, String> resultPair6=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair6.first().intValue());
		
		List<Pair<String, String>> devices= new ArrayList<Pair<String,String>>();
		Pair<String, String> device1=new Pair<String, String>();
		device1.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
		device1.second("test_subuser1");
		devices.add(device1);

		String marker=AssertListVirtualMFADevicesResult(resultPair6.second(), devices, true);
        
		body="Action=ListVirtualMFADevices&Version=2010-05-08&AssignmentStatus=Assigned&MaxItems=1&Marker="+marker;
        Pair<Integer, String> resultPair7=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair7.first().intValue());
		
		List<Pair<String, String>> devices2= new ArrayList<Pair<String,String>>();
		Pair<String, String> device2=new Pair<String, String>();
		device2.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
		device2.second("test_subuser2");
		devices2.add(device2);
		
		AssertListVirtualMFADevicesResult(resultPair7.second(), devices2, false);
	}
	
	@Test
	/*
	 * list 设备，AssignmentStatus参数为Unassigned分页查询
	 */
	public void test_listVirtualMFADevices_Unassigned_maxItmes1() throws Exception{

		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa2";
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair3.first().intValue());
        AssertcreateVirtualMFADevice(resultPair3.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa3";
        Pair<Integer, String> resultPair4=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair4.first().intValue());
        AssertcreateVirtualMFADevice(resultPair4.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa3");
        
        
        body="Action=ListVirtualMFADevices&Version=2010-05-08&AssignmentStatus=Unassigned&MaxItems=1";
        Pair<Integer, String> resultPair5=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair5.first().intValue());
        
		List<Pair<String, String>> devices= new ArrayList<Pair<String,String>>();
		Pair<String, String> device2=new Pair<String, String>();
		device2.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
		devices.add(device2);
		String marker=AssertListVirtualMFADevicesResult(resultPair5.second(), devices, true);
		
		body="Action=ListVirtualMFADevices&Version=2010-05-08&AssignmentStatus=Unassigned&MaxItems=1&Marker="+marker;
        Pair<Integer, String> resultPair6=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair6.first().intValue());
		
		List<Pair<String, String>> devices2= new ArrayList<Pair<String,String>>();
		Pair<String, String> device3=new Pair<String, String>();
		device3.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa3");
		devices2.add(device3);
		AssertListVirtualMFADevicesResult(resultPair6.second(), devices2, false);
	}
	
	@Test
    /*
     * list 设备
     */
    public void test_listMFADevices_NoUserName_Root() throws Exception{

        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa2";
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair3.first().intValue());
        AssertcreateVirtualMFADevice(resultPair3.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
        
        
        body="Action=ListMFADevices&Version=2010-05-08";
        Pair<Integer, String> resultPair4=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair4.first().intValue());
        
        AssertListMFADevicesResult(resultPair4.second(), null, false);
    }
	
	@Test
    /*
     * list 设备
     */
    public void test_listMFADevices_NoUserName_User() throws Exception{

	    String UserName1="subuser1";
        String user1accessKey1="abc1234567890";
        String user1secretKey1="sdfghjkl123456789";
        String accountId="3rmoqzn03g6ga";
        
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
        HBaseUtils.put(user1);
        
        String policyName="listDevice";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:ListMFADevices"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, UserName1, policyName, 200);

	    
        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName="+UserName1+"&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa2";
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair3.first().intValue());
        AssertcreateVirtualMFADevice(resultPair3.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
        
        body="Action=ListMFADevices&Version=2010-05-08";
        Pair<Integer, String> resultPair4=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, resultPair4.first().intValue());
        
        List<Pair<String, String>> devices= new ArrayList<Pair<String,String>>();
        Pair<String, String> device1=new Pair<String, String>();
        device1.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        device1.second(UserName1);
        devices.add(device1);
        
        AssertListMFADevicesResult(resultPair4.second(), devices, false);
    }

	@Test
    /*
     * list 设备
     */
    public void test_listMFADevices_user() throws Exception{

        String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa2";
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair3.first().intValue());
        AssertcreateVirtualMFADevice(resultPair3.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa2");
        
        body="Action=ListMFADevices&Version=2010-05-08&UserName=test_subuser1";
        Pair<Integer, String> resultPair4=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair4.first().intValue());
        
        List<Pair<String, String>> devices= new ArrayList<Pair<String,String>>();
        Pair<String, String> device1=new Pair<String, String>();
        device1.first("arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        device1.second("test_subuser1");
        devices.add(device1);
        
        AssertListMFADevicesResult(resultPair4.second(), devices, false);
    }

	@Test
	/*
	 * 删除设备
	 */
	public void test_deleteVirtualMFADevice() throws Exception{
		String deviceName="abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx";
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName="+deviceName;
	    Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
	    AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/"+deviceName);
		
		
        String SerialNumber="arn:ctyun:iam::3rmoqzn03g6ga:mfa/"+deviceName;
        body="Action=DeleteVirtualMFADevice&SerialNumber="+UrlEncoded.encodeString(SerialNumber);
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair2.first().intValue());
	}
	
	@Test
	/*
	 * 删除已经绑定正在使用的设备
	 */
	public void test_deleteVirtualMFADevice_InUse() throws Exception{
		
		String body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName=test_subuser1&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
        
        body="Action=DeleteVirtualMFADevice&SerialNumber="+UrlEncoded.encodeString(SerialNumber);
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(409, resultPair3.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair3.second());
        assertEquals("DeleteConflict", error.get("Code"));
		assertEquals("MFA VirtualDevice in use. Must deactivate first.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
        
	}
	
	@Test
	/*
	 * 删除不存在的设备
	 */
	public void test_deleteVirtualMFADevice_SerialNumber_Error() throws Exception{
        
        String SerialNumber="arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa11111111";
        String body="Action=DeleteVirtualMFADevice&SerialNumber="+UrlEncoded.encodeString(SerialNumber);
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(404, resultPair3.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair3.second());
        assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("VirtualMFADevice with serial number arn:ctyun:iam::3rmoqzn03g6ga:mfa/mfa11111111 does not exist.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
        
	}
	
	@Test
	/*
	 * 删除不存在的设备SerialNumber参数不存在
	 */
	public void test_deleteVirtualMFADevice_NoSerialNumberParam() throws Exception{

        String body="Action=DeleteVirtualMFADevice";
        Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, resultPair3.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair3.second());
        assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'serialNumber' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("/", error.get("Resource"));
       
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
	
	public static String AssertListVirtualMFADevicesResult(String xml,List<Pair<String, String>> devices,boolean isTruncate) {
		String marker="";
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        Element resultElement=root.getChild("ListVirtualMFADevicesResult");
	        assertEquals(String.valueOf(isTruncate), resultElement.getChild("IsTruncated").getValue());
	        if(isTruncate) {
	        	marker=resultElement.getChild("Marker").getValue();
	        }

	        Element virtualMFADevicesElement=resultElement.getChild("VirtualMFADevices");
	        List<Element> members=virtualMFADevicesElement.getChildren("member");
	        
	        if (devices!=null && devices.size()>0) {
				for (int i = 0; i < devices.size(); i++) {
					assertEquals(devices.get(i).first(), members.get(i).getChild("SerialNumber").getValue());
					if (devices.get(0).second()!=null) {
						System.out.println("EnableDate="+members.get(i).getChild("EnableDate").getValue());
						Element userElement=members.get(i).getChild("User");
						assertEquals(devices.get(i).second(), userElement.getChild("UserName").getValue());
						System.out.println("UserId="+userElement.getChild("UserId").getValue());
						System.out.println("CreateDate="+userElement.getChild("CreateDate").getValue());
						System.out.println("PasswordLastUsed="+userElement.getChild("PasswordLastUsed").getValue());
						System.out.println("Arn="+userElement.getChild("Arn").getValue());
					}
				}
			}
	        
		} catch (Exception e) {
			// TODO: handle exception
		}
		
		return marker;
	}
	
	public static String AssertListMFADevicesResult(String xml,List<Pair<String, String>> devices,boolean isTruncate) {
        String marker="";
        try {
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = doc.getRootElement();
            
            Element resultElement=root.getChild("ListMFADevicesResult");
            assertEquals(String.valueOf(isTruncate), resultElement.getChild("IsTruncated").getValue());
            if(isTruncate) {
                marker=resultElement.getChild("Marker").getValue();
            }

            Element virtualMFADevicesElement=resultElement.getChild("MFADevices");
            List<Element> members=virtualMFADevicesElement.getChildren("member");
            
            if (devices!=null && devices.size()>0) {
                for (int i = 0; i < devices.size(); i++) {
                    assertEquals(devices.get(i).first(), members.get(i).getChild("SerialNumber").getValue());
                    if (devices.get(0).second()!=null) {
                        System.out.println("EnableDate="+members.get(i).getChild("EnableDate").getValue());
                        Element userElement=members.get(i).getChild("User");
                        assertEquals(devices.get(i).second(), userElement.getChild("UserName").getValue());
                    }
                }
            }
            
        } catch (Exception e) {
            // TODO: handle exception
        }
        
        return marker;
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

}
