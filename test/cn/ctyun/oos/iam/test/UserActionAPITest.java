package cn.ctyun.oos.iam.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.StringReader;
import java.net.URLEncoder;
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
import org.apache.hadoop.hbase.util.Bytes;
import org.eclipse.jetty.util.UrlEncoded;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.server.entity.MFADevice;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.internal.api.IAMInternalAPI;
import cn.ctyun.oos.iam.server.internal.api.LoginParam;
import cn.ctyun.oos.iam.server.internal.api.LoginResult;
import cn.ctyun.oos.iam.server.service.AccessKeyService;
import cn.ctyun.oos.iam.signer.Misc;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class UserActionAPITest {
	
	
	private static String ownerName = "root_user1@test.com";
	public static final String accessKey="userak1";
	public static final String secretKey="usersk1";
	
	private static String ownerName2 = "root_user2@test.com";
	public static final String accessKey2="userak2";
	public static final String secretKey2="usersk2";
	
	public static OwnerMeta owner = new OwnerMeta(ownerName);
	public static OwnerMeta owner2 = new OwnerMeta(ownerName2);
    public static MetaClient metaClient = MetaClient.getGlobalClient();
	

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	    IAMTestUtils.TrancateTable("oos-aksk-yx");
		IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);
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
		
		// 创建根用户1
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

	}

	@Before
	public void setUp() throws Exception {
		IAMTestUtils.TrancateTable("iam-user-yx");
		IAMTestUtils.TrancateTable("iam-passwordPolicy-yx");
	}

	@Test
	/*
	 * 创建账户
	 */
	public void test_createUser() throws Exception {
		String UserName="subuser_test2";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(resultPair.second(), UserName, tags);
	}
	
	@Test
	/*
	 * 同一个用户创建同名账号，且大小写一致
	 */
	public void test_createUser_SameNameInOneAcccount() throws Exception {
		String UserName="subuser_test2";
		String tag1Key="email";
		String tag1value="test1@oos.com";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag1Key+"&Tags.member.1.Value="+tag1value;
		
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		// 同名且大小写一致
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409, resultPair2.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair2.second());
		assertEquals("EntityAlreadyExists", error.get("Code"));
		assertEquals("User with name "+UserName+" already exists.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
		
	}
	
	@Test
	/*
	 * 同一个用户创建同名账号，且大小写不一致
	 */
	public void test_createUser_SameNameInOneAcccount2() throws Exception {
		String UserName="subuser_test3";
		String tag1Key="email";
		String tag1value="test1@oos.com";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag1Key+"&Tags.member.1.Value="+tag1value;
		
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		// 同名且大小写一致
		UserName="SubUSER_Test3";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag1Key+"&Tags.member.1.Value="+tag1value;
				
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409, resultPair2.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair2.second());
		assertEquals("EntityAlreadyExists", error.get("Code"));
		assertEquals("User with name "+UserName+" already exists.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
		
	}
	
	@Test
	/*
	 * 不同账号建同名子账号
	 */
	public void test_createUser_SameNameInTwoAcccount() throws Exception {
		String UserName="subuser_test4";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(resultPair.second(), UserName, tags);
		
		// 同名且大小写一致
		UserName="subuser_test4";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
				
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey2, secretKey2);
		assertEquals(200, resultPair2.first().intValue());
		AssertCreateUserResult(resultPair2.second(), UserName, tags);	

	}
	
	@Test
	/*
	 * 创建账户,两个标签
	 */
	public void test_createUser_TwoTags() throws Exception {
		String UserName="subuser_test5";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		Pair<String, String> tag2=new Pair<String, String>();
		tag2.first("phone");
		tag2.second("12345678901");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second()+"&Tags.member.2.Key="+tag2.first()+"&Tags.member.2.Value="+tag2.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		tags.add(tag2);
		AssertCreateUserResult(resultPair.second(), UserName, tags);
	}
	
	@Test
	/*
	 * 创建账户,两个标签
	 */
	public void test_createUser_TwoSameTags() throws Exception {
		String UserName="subuser_test5";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		Pair<String, String> tag2=new Pair<String, String>();
		tag2.first("email");
		tag2.second("12345678901");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second()+"&Tags.member.2.Key="+tag2.first()+"&Tags.member.2.Value="+tag2.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("InvalidInput", error.get("Code"));
		assertEquals("Duplicate tag keys found. Please note that Tag keys are case insensitive.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 创建账户,没有标签
	 */
	public void test_createUser_NoTag() {
		String UserName="subuser_test1";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
	}
	
	@Test
	/*
	 * 创建账户,标签10个
	 */
	public void test_createUser_10Tag() {
		String UserName="subuser_10Tag";
		String tagString="";
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		for (int i = 1; i <= 10; i++) {
			Pair<String, String> tag=new Pair<String, String>();
			tag.first("key"+i);
			tag.second("value"+i);
			tags.add(tag);
			tagString+="&Tags.member."+i+".Key="+tag.first()+"&Tags.member."+i+".Value="+tag.second();
		}
		
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		
		AssertCreateUserResult(resultPair.second(), UserName, tags);
	}
	
	@Test
	/*
	 * 创建账户,标签11个
	 */
	public void test_createUser_11Tag() throws JSONException {
		String UserName="subuser_11Tag";
		String tagString="";
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		for (int i = 1; i <= 11; i++) {
			Pair<String, String> tag=new Pair<String, String>();
			tag.first("key"+i);
			tag.second("value"+i);
			tags.add(tag);
			tagString+="&Tags.member."+i+".Key="+tag.first()+"&Tags.member."+i+".Value="+tag.second();
		}
		
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("MalformedInput", error.get("Code"));
		assertEquals("11 is not a valid index.", error.get("Message"));
	}
	
	@Test
	/*
	 * 创建账户,用户名包含空格
	 */
	public void test_createUser_UserNameContainsBlank() throws JSONException {
		String UserName="subuser test1";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UrlEncoded.encodeString(UserName);
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'userName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
		
	}
	
	
	
	@Test
	/*
	 * 创建账户,用户名参数不存在
	 */
	public void test_createUser_NoUserNameParam() throws JSONException {
		String body="Action=CreateUser&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * 创建账户,用户名不传值
	 */
	public void test_createUser_UserName0Character() throws JSONException {
		String UserName="";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UrlEncoded.encodeString(UserName);
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'userName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * 创建账户,用户名1个字符
	 */
	public void test_createUser_UserName1Character() {
		String UserName="1";
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
	}
	
	@Test
	/*
	 * 创建账户,用户名64个字符
	 */
	public void test_createUser_UserName64Character() {
		String UserName="1234567890123456789012345678901234567890123456789012345678901234";
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
	}
	
	@Test
	/*
	 * 创建账户,用户名65个字符
	 */
	public void test_createUser_UserName65Character() throws JSONException {
		String UserName="12345678901234567890123456789012345678901234567890123456789012345";
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '"+UserName+"' at 'userName' failed to satisfy constraint: Member must have length less than or equal to 64", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 创建账户,用户名包含特殊字符_ + =，.@ -
	 */
	public void test_createUser_UserNameSpecialCharacter() {
		String UserName="yan_xiao1111@163.com,test-1+2=hello";
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UrlEncoded.encodeString(UserName);
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
	}
	
	@Test
	/*
	 * 创建账户超过500
	 */
	public void test_createUser_morethan500() throws JSONException {
		IAMTestUtils.TrancateTable("iam-user-yx");
		
		for (int i = 1; i <= 500; i++) {
			String UserName="test_"+i;
			String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
			Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
			
			assertEquals(200, resultPair.first().intValue());
			AssertCreateUserResult(resultPair.second(), UserName, null);
		}
		
		String UserName="test_501";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(409, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("LimitExceeded", error.get("Code"));
		assertEquals("Cannot exceed quota for UsersPerAccount: 500.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
		// 实际 Cannot exceed quota for UsersPerAccount:5000.
	}
	
	@Test
	/*
	 * 创建账户,tag key 是空
	 */
	public void test_createUser_TagKey0Character_bug() throws Exception {
		String UserName="subuser_tag0";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '' at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 创建账户,tag value 是空
	 */
	public void test_createUser_TagValue0Character() throws Exception {
		String UserName="subuser_tag0";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
	}
	
	@Test
	/*
	 * 创建账户,tag Key参数不存在
	 */
	public void test_createUser_NoTagKeyParam() throws Exception {
		String UserName="subuser_tag0";
		Pair<String, String> tag=new Pair<String, String>();
		tag.second("email");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'tags.1.member.key' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 创建账户,tag value 参数不存在
	 */
	public void test_createUser_NoTagValueParam() throws Exception {
		String UserName="subuser_tag0";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(400, resultPair.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(resultPair.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'tags.1.member.value' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 删除用户
	 */
	public void test_deleteUser() throws Exception {
		// 创建用户
		String UserName="subuser_testDel";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(resultPair.second(), UserName, tags);
		
		// 删除用户
		body="Action=DeleteUser&UserName="+UserName;
		Pair<Integer, String> deleteresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, deleteresult.first().intValue());
		
	}
	
	@Test
	/*
	 * 删除用户长度为1
	 */
	public void test_deleteUser_UserName1Character() {
		String UserName="1";
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		body="Action=DeleteUser&UserName="+UserName;
		Pair<Integer, String> deleteresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, deleteresult.first().intValue());
	}
	
	@Test
	/*
	 * 删除用户长度为64
	 */
	public void test_deleteUser_UserName64Character() {
		String UserName="1234567890123456789012345678901234567890123456789012345678901234";
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		body="Action=DeleteUser&UserName="+UserName;
		Pair<Integer, String> deleteresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, deleteresult.first().intValue());
	}
	
	
	@Test
	/*
	 * 删除用户长度为65（创建不了65个字符的用户，所以用户不存在）
	 */
	public void test_deleteUser_nouser_UserName65Character() throws JSONException {
		String UserName="12345678901234567890123456789012345678901234567890123456789012345";
		
		String body="Action=DeleteUser&UserName="+UserName;
		Pair<Integer, String> deleteresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, deleteresult.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(deleteresult.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '"+UserName+"' at 'userName' failed to satisfy constraint: Member must have length less than or equal to 64", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 删除不存在的用户
	 */
	public void test_deleteUser_noUser() throws JSONException {
		String UserName="nouser";
		
		String body="Action=DeleteUser&UserName="+UserName;
		Pair<Integer, String> deleteresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, deleteresult.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(deleteresult.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name "+UserName+" cannot be found.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 删除usertname不存在
	 */
	public void test_deleteUser_noUserNameParam() throws JSONException {
		
		String body="Action=DeleteUser";
		Pair<Integer, String> deleteresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, deleteresult.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(deleteresult.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * 删除用户长度为0
	 */
	public void test_deleteUser_UserName0Character() throws JSONException {
		
		String body="Action=DeleteUser&UserName=";
		Pair<Integer, String> deleteresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, deleteresult.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(deleteresult.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'userName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * 用户属于某个组时，不允许删除
	 */
	public void test_deleteUser_userHasGroup() throws JSONException {
		// 创建用户
		String UserName="subuser_testgroup";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(resultPair.second(), UserName, tags);
		
		// 创建组
		String groupName="group1";
		body="GroupName="+groupName+"&Action=CreateGroup";
		Pair<Integer, String> grouPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, grouPair.first().intValue());
		
		// 把用户加到组内
		body="GroupName="+groupName+"&Action=AddUserToGroup&UserName="+UserName;
		Pair<Integer, String> addgrouPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addgrouPair.first().intValue());
		
		// 删除用户
		body="Action=DeleteUser&UserName="+UserName;
		Pair<Integer, String> deleteresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409, deleteresult.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(deleteresult.second());
		assertEquals("DeleteConflict", error.get("Code"));
		assertEquals("Cannot delete entity, must remove users from group first.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 用户有登录密码时，不允许删除
	 */
	public void test_deleteUser_userHasPassword() throws JSONException {
		// 创建用户
		String UserName="subuser_testpasswd";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(resultPair.second(), UserName, tags);
		
		// 设置登录密码
		body="Action=CreateLoginProfile&UserName="+UserName+"&Password=a12345678&PasswordResetRequired=true";
		Pair<Integer, String> setps=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, setps.first().intValue());
		
		// 删除用户
		body="Action=DeleteUser&UserName="+UserName;
		Pair<Integer, String> deleteresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409, deleteresult.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(deleteresult.second());
		assertEquals("DeleteConflict", error.get("Code"));
		assertEquals("Cannot delete entity, must delete login profile first.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 用户分配了策略，不允许删除
	 */
	public void test_deleteUser_userHasPolicy() throws JSONException {
		// 创建用户
		String UserName="subuser_testpolicy";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(resultPair.second(), UserName, tags);
		
		// 添加策略
		body="Action=CreatePolicy&Version=2010-05-08&PolicyName=fullaccess&PolicyDocument={\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"*\",\"Resource\": \"*\"}]}";
		Pair<Integer, String> addPolicy=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addPolicy.first().intValue());
		
		// 添加策略给用户
		body="Action=AttachUserPolicy&PolicyArn=arn:ctyun:iam::3fdmxmc3pqvmp:policy/fullaccess&UserName="+UserName;
		Pair<Integer, String> addPolicyToUser=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addPolicyToUser.first().intValue());
		
		// 删除用户
		body="Action=DeleteUser&UserName="+UserName;
		Pair<Integer, String> deleteresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409, deleteresult.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(deleteresult.second());
		assertEquals("DeleteConflict", error.get("Code"));
		assertEquals("Cannot delete entity, must detach all policies first.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 用户有aksk时，不允许删除
	 */
	public void test_deleteUser_userHasAksk() throws JSONException {
		// 创建用户
		String UserName="subuser_testaksk";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(resultPair.second(), UserName, tags);
		// 分配aksk
		body="Action=CreateAccessKey&UserName="+UserName;
		Pair<Integer, String> createakResult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createakResult.first().intValue());
		
		// 删除
		body="Action=DeleteUser&UserName="+UserName;
		Pair<Integer, String> deleteresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409, deleteresult.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(deleteresult.second());
		assertEquals("DeleteConflict", error.get("Code"));
		assertEquals("Cannot delete entity, must delete access keys first.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 用户有绑定设备，提示要先删除设备
	 */
	public void test_deleteUser_userHasMfa() throws JSONException {
		// 创建用户
		String UserName="subuser_test1";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> createUser=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, createUser.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(createUser.second(), UserName, tags);
		// 创建设备
		body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(resultPair.second(), "arn:ctyun:iam::3fdmxmc3pqvmp:mfa/mfa1");
        
        // 绑定设备
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName="+UserName+"&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair2.first().intValue());
		
		// 删除用户
        body="Action=DeleteUser&UserName="+UserName;
		Pair<Integer, String> deleteresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409, deleteresult.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(deleteresult.second());
		assertEquals("DeleteConflict", error.get("Code"));
		assertEquals("Cannot delete entity, must delete MFA device first.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 获取用户
	 */
	public void test_getUser() throws Exception {
		// 创建用户
		String UserName="subuser_testget";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(resultPair.second(), UserName, tags);
		
		// 用户设置密码
		body="Action=CreateLoginProfile&UserName="+UserName+"&Password=a12345678";
		Pair<Integer, String> setPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, setPasswd.first().intValue());
		// 用户登录
		LoginParam loginParam = new LoginParam();
        loginParam.accountId = "3fdmxmc3pqvmp";
        loginParam.userName = UserName;
        loginParam.passwordMd5 = Misc.getMd5("a12345678");
        loginParam.loginIp="192.168.1.1";
        
        LoginResult loginResult = IAMInternalAPI.login(loginParam);
		
		// 获取用户
		body="Action=GetUser&UserName="+UserName;
		Pair<Integer, String> getresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, getresult.first().intValue());
		AssertGetUserResult(getresult.second(), UserName, tags);
	}
	
	@Test
	/*
	 * 获取用户长度为1
	 */
	public void test_getUser_UserName1Character() {
		String UserName="1";
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		body="Action=GetUser&UserName="+UserName;
		Pair<Integer, String> getresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, getresult.first().intValue());
		AssertGetUserResult(getresult.second(), UserName, null);
	}
	
	@Test
	/*
	 * 获取用户长度为64
	 */
	public void test_getUser_UserName64Character() {
		String UserName="1234567890123456789012345678901234567890123456789012345678901234";
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		body="Action=GetUser&UserName="+UserName;
		Pair<Integer, String> getresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, getresult.first().intValue());
		AssertGetUserResult(getresult.second(), UserName, null);
	}
	
	
	@Test
	/*
	 * 获取用户长度为65（创建不了65个字符的用户，所以用户不存在）
	 */
	public void test_getUser_nouser_UserName65Character() throws JSONException {
		String UserName="12345678901234567890123456789012345678901234567890123456789012345";
		
		String body="Action=GetUser&UserName="+UserName;
		Pair<Integer, String> getUser=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, getUser.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(getUser.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '"+UserName+"' at 'userName' failed to satisfy constraint: Member must have length less than or equal to 64", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 获取不存在的用户
	 */
	public void test_getUser_noUser() throws JSONException {
		String UserName="nouser";
		
		String body="Action=GetUser&UserName="+UserName;
		Pair<Integer, String> getresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, getresult.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(getresult.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name "+UserName+" cannot be found.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 获取usertname不存在，根据ak判断，根用户
	 */
	public void test_getUser_noUserNameParam_Root() throws JSONException {
		
		String body="Action=GetUser";
		Pair<Integer, String> getresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, getresult.first().intValue());
		AssertGetUserResult(getresult.second(), ownerName, null);
	}
	
	@Test
    /*
     * 获取usertname不存在，根据ak判断，子用户
     */
    public void test_getUser_noUserNameParam_User() throws JSONException, IOException {
	    
	    String UserName1="subuser1";
	    String user1accessKey1="abc1234567890";
	    String user1secretKey1="sdfghjkl123456789";
	    String accountId="3fdmxmc3pqvmp";
	    
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
        
        String policyName="getuser";
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:GetUser"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+":user/*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, UserName1, policyName, 200);
        
        String body="Action=GetUser";
        Pair<Integer, String> getresult=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, getresult.first().intValue());
        AssertGetUserResult(getresult.second(), UserName1, null);
    }
	
	@Test
	/*
	 * get用户长度为0
	 */
	public void test_getUser_UserName0Character() throws JSONException {
		
		String body="Action=GetUser&UserName=";
		Pair<Integer, String> getresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, getresult.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(getresult.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'userName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * 创建两个用户list不加前缀情况list用户
	 */
	public void test_listUsers() throws Exception {
		Map<String, Pair<Integer, Integer>> users1Map=new HashMap<String, Pair<Integer,Integer>>();

		String UserName="subuser_test1";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, tags);
		
		body="Action=CreateLoginProfile&UserName="+UserName+"&Password=a12345678";
		Pair<Integer, String> setps=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, setps.first().intValue());
		
		LoginParam loginParam = new LoginParam();
        loginParam.accountId = "3fdmxmc3pqvmp";
        loginParam.userName = UserName;
        loginParam.passwordMd5 = Misc.getMd5("a12345678");
        
        LoginResult loginResult = IAMInternalAPI.login(loginParam);
        
        body="Action=CreateAccessKey&UserName="+UserName;
        Pair<Integer, String> akresultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, akresultPair.first().intValue());  
        
        Pair<Integer, String> akresultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, akresultPair2.first().intValue()); 
        
        Pair<Integer, Integer> user1Pair=new Pair<Integer, Integer>();
        user1Pair.first(2);
        user1Pair.second(0);
        users1Map.put(UserName, user1Pair);
		
		UserName="subuser_test2";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair2.first().intValue());
		AssertCreateUserResult(resultPair2.second(), UserName, null);
		
		body="Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=mfa1";
        Pair<Integer, String> mfaresultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, mfaresultPair.first().intValue());
        Pair<String, String> devicePair=AssertcreateVirtualMFADevice(mfaresultPair.second(), "arn:ctyun:iam::3fdmxmc3pqvmp:mfa/mfa1");
        
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        body="Action=EnableMFADevice&Version=2010-05-08&UserName="+UserName+"&SerialNumber="+UrlEncoded.encodeString(SerialNumber)+"&AuthenticationCode1="+codesPair.first()+"&AuthenticationCode2="+codesPair.second();
        Pair<Integer, String> mfaresultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, mfaresultPair2.first().intValue());
        
        Pair<Integer, Integer> user2Pair=new Pair<Integer, Integer>();
        user2Pair.first(0);
        user2Pair.second(1);
        users1Map.put(UserName, user2Pair);
		
		UserName="subuser_test3";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey2, secretKey2);
		
		assertEquals(200, resultPair3.first().intValue());
		AssertCreateUserResult(resultPair3.second(), UserName, null);

		Map<String, Pair<Integer, Integer>> users2Map=new HashMap<String, Pair<Integer,Integer>>();
		Pair<Integer, Integer> user3Pair=new Pair<Integer, Integer>();
        user3Pair.first(0);
        user3Pair.second(0);
        users2Map.put(UserName, user3Pair);
		
		// list
		body="Action=ListUsers&Version=2010-05-08";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult.first().intValue());
		
		AssertlistUsersResult(listresult.second(), users1Map,false);
		
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(body, accessKey2, secretKey2);
		assertEquals(200, listresult2.first().intValue());
		AssertlistUsersResult(listresult2.second(), users2Map,false);
		
	}
	
	
	
	@Test
	/*
	 * 账户下没有用户情况list
	 */
	public void test_listUsers_noUser() {
		String body="Action=ListUsers&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertlistUsersResult(resultPair.second(), null,false);
	}
	
	@Test
	/*
	 * 创建test_1,test_2 ,abc1用test_1 匹配
	 */
	public void test_listUsers_userNameMatch() {
		String UserName1="test_1";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName1+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(resultPair.second(), UserName1, tags);
		
		String UserName2="test_2";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName2;
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair2.first().intValue());	
		AssertCreateUserResult(resultPair2.second(), UserName2, null);
		
		String UserName3="abc1";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName3;
		Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair3.first().intValue());	
		AssertCreateUserResult(resultPair3.second(), UserName3, null);
		
		// 用test_1匹配
		body="Action=ListUsers&Version=2010-05-08&UserName=test_1";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult.first().intValue());
		Map<String, Pair<Integer, Integer>> users1Map=new HashMap<String, Pair<Integer,Integer>>();
		Pair<Integer, Integer> user1Pair=new Pair<Integer, Integer>();
	    user1Pair.first(0);
	    user1Pair.second(0);
	    users1Map.put(UserName1, user1Pair);
		AssertlistUsersResult(listresult.second(), users1Map,false);
		
		
		
	}
	
	@Test
	/*
	 * 创建test_1,test_2,abc1 用test 匹配
	 */
	public void test_listUsers_userNameMatch2() {
		String UserName1="test_1";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName1+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(resultPair.second(), UserName1, tags);
		
		String UserName2="test_2";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName2;
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair2.first().intValue());	
		AssertCreateUserResult(resultPair2.second(), UserName2, null);
		
		String UserName3="abc1";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName3;
		Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair3.first().intValue());	
		AssertCreateUserResult(resultPair3.second(), UserName3, null);
		
		// 用test_1匹配
		body="Action=ListUsers&Version=2010-05-08&UserName=test";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult.first().intValue());
		
		Map<String, Pair<Integer, Integer>> users1Map=new HashMap<String, Pair<Integer,Integer>>();
        Pair<Integer, Integer> user1Pair=new Pair<Integer, Integer>();
        user1Pair.first(0);
        user1Pair.second(0);
        users1Map.put(UserName1, user1Pair);
        Pair<Integer, Integer> user2Pair=new Pair<Integer, Integer>();
        user2Pair.first(0);
        user2Pair.second(0);
        users1Map.put(UserName2, user2Pair);
		AssertlistUsersResult(listresult.second(), users1Map,false);
	}
	
	@Test
	/*
	 * 创建test_1,test_2,abc1 用_ 匹配
	 */
	public void test_listUsers_userNameMatch3() {
		String UserName1="test_1";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName1+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(resultPair.second(), UserName1, tags);
		
		String UserName2="test_2";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName2;
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair2.first().intValue());	
		AssertCreateUserResult(resultPair2.second(), UserName2, null);
		
		String UserName3="abc1";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName3;
		Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair3.first().intValue());	
		AssertCreateUserResult(resultPair3.second(), UserName3, null);
		
		// 用_匹配
		body="Action=ListUsers&Version=2010-05-08&UserName=_";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult.first().intValue());
		Map<String, Pair<Integer, Integer>> users1Map=new HashMap<String, Pair<Integer,Integer>>();
        Pair<Integer, Integer> user1Pair=new Pair<Integer, Integer>();
        user1Pair.first(0);
        user1Pair.second(0);
        users1Map.put(UserName1, user1Pair);
        Pair<Integer, Integer> user2Pair=new Pair<Integer, Integer>();
        user2Pair.first(0);
        user2Pair.second(0);
        users1Map.put(UserName2, user2Pair);
		AssertlistUsersResult(listresult.second(), users1Map,false);
	}
	
	@Test
	/*
	 * 创建test_1,test_2 ,abc1用1 匹配
	 */
	public void test_listUsers_userNameMatch4() {
		String UserName1="test_1";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName1+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(resultPair.second(), UserName1, tags);
		
		String UserName2="test_2";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName2;
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair2.first().intValue());	
		AssertCreateUserResult(resultPair2.second(), UserName2, null);
		
		String UserName3="abc1";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName3;
		Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair3.first().intValue());	
		AssertCreateUserResult(resultPair3.second(), UserName3, null);
		
		// 用1匹配
		body="Action=ListUsers&Version=2010-05-08&UserName=1";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult.first().intValue());
		Map<String, Pair<Integer, Integer>> users1Map=new HashMap<String, Pair<Integer,Integer>>();
        Pair<Integer, Integer> user1Pair=new Pair<Integer, Integer>();
        user1Pair.first(0);
        user1Pair.second(0);
        users1Map.put(UserName1, user1Pair);
        Pair<Integer, Integer> user2Pair=new Pair<Integer, Integer>();
        user2Pair.first(0);
        user2Pair.second(0);
        users1Map.put(UserName3, user2Pair);
		AssertlistUsersResult(listresult.second(), users1Map,false);
	}
	
	@Test
	/*
	 * 创建test_1,test_2 ,abc1用def匹配
	 */
	public void test_listUsers_userNameMatch5() {
		String UserName1="test_1";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName1+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(resultPair.second(), UserName1, tags);
		
		String UserName2="test_2";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName2;
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair2.first().intValue());	
		AssertCreateUserResult(resultPair2.second(), UserName2, null);
		
		String UserName3="abc1";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName3;
		Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair3.first().intValue());	
		AssertCreateUserResult(resultPair3.second(), UserName3, null);
		
		// 用def匹配
		body="Action=ListUsers&Version=2010-05-08&UserName=def";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult.first().intValue());
		AssertlistUsersResult(listresult.second(), null,false);
	}
	
	@Test
	/*
	 * 用户1创建test_1,test_2 ,用户2创建abc1用1匹配
	 */
	public void test_listUsers_userNameMatch6() {
		String UserName1="test_1";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName1+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertCreateUserResult(resultPair.second(), UserName1, tags);
		
		String UserName2="test_2";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName2;
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair2.first().intValue());	
		AssertCreateUserResult(resultPair2.second(), UserName2, null);
		
		String UserName3="abc1";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName3;
		Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey2, secretKey2);
		
		assertEquals(200, resultPair3.first().intValue());	
		AssertCreateUserResult(resultPair3.second(), UserName3, null);
		
		// 用1匹配
		body="Action=ListUsers&Version=2010-05-08&UserName=1";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey2, secretKey2);
		assertEquals(200, listresult.first().intValue());
		Map<String, Pair<Integer, Integer>> users1Map=new HashMap<String, Pair<Integer,Integer>>();
        Pair<Integer, Integer> user1Pair=new Pair<Integer, Integer>();
        user1Pair.first(0);
        user1Pair.second(0);
        users1Map.put(UserName3, user1Pair);
		AssertlistUsersResult(listresult.second(), users1Map,false);
	}
	
	@Test
	/*
	 * 创建test_1,test_2 ,abc1 
	 * test_1创建两个ak，test_2和abc1各创建一个ak
	 * 用 ak匹配 ,完全匹配
	 */
	public void test_listUsers_akMatch() throws IOException {
		String UserName1="test_1";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName1+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		String userId1=AssertCreateUserResult(resultPair.second(), UserName1, tags);

		// 插入数据库aksk
		AkSkMeta aksk = new AkSkMeta(owner.getId());
        aksk.isRoot = 0;
        aksk.userId = userId1;
        aksk.userName = UserName1;
        aksk.accessKey="abcdefgh";
        aksk.setSecretKey("ccccccccc");
        metaClient.akskInsert(aksk);
        User user1 = new User();
        user1.accountId = "3fdmxmc3pqvmp";
        user1.userName = UserName1;
        user1.accessKeys = new ArrayList<>();
        user1.accessKeys.add(aksk.accessKey);
        
        aksk.accessKey="12345678";
        aksk.setSecretKey("world");
        metaClient.akskInsert(aksk);
        user1.accessKeys.add(aksk.accessKey);
        HBaseUtils.put(user1);
		
		String UserName2="test_2";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName2;
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair2.first().intValue());
		String userId2=AssertCreateUserResult(resultPair2.second(), UserName2, null);
		
		AkSkMeta aksk2 = new AkSkMeta(owner.getId());
        aksk2.isRoot = 0;
        aksk2.userId = userId2;
        aksk2.userName = UserName2;
        aksk2.accessKey="highlmn";
        aksk2.setSecretKey("ffffffffff");
        metaClient.akskInsert(aksk2);
        User user2 = new User();
        user2.accountId = "3fdmxmc3pqvmp";
        user2.userName = UserName1;
        user2.accessKeys = new ArrayList<>();
        user2.userName=UserName2;
        user2.accessKeys.add(aksk2.accessKey);
        HBaseUtils.put(user2);
		
		String UserName3="abc1";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName3;
		Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair3.first().intValue());
		String userId3=AssertCreateUserResult(resultPair3.second(), UserName3, null);
		
		AkSkMeta aksk3 = new AkSkMeta(owner.getId());
		aksk3.isRoot = 0;
		aksk3.userId = userId3;
		aksk3.userName = UserName3;
		aksk3.accessKey="fgh123";
		aksk3.setSecretKey("jjjjjjjjjjjjj");
        metaClient.akskInsert(aksk3);
        
        User user3 = new User();
        user3.accountId = "3fdmxmc3pqvmp";
        user3.userName = UserName1;
        user3.accessKeys = new ArrayList<>();
        user3.userName=UserName3;
        user3.accessKeys.add(aksk3.accessKey);
        HBaseUtils.put(user3);
		
		// list ak匹配
		body="Action=ListUsers&Version=2010-05-08&AccessKeyId=fgh123";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult.first().intValue());
		
		Map<String, Pair<Integer, Integer>> users1Map=new HashMap<String, Pair<Integer,Integer>>();
        Pair<Integer, Integer> user1Pair=new Pair<Integer, Integer>();
        user1Pair.first(1);
        user1Pair.second(0);
        users1Map.put(UserName3, user1Pair);
		AssertlistUsersResult(listresult.second(), users1Map,false);

	}
	
	@Test
	/*
	 * 创建test_1,test_2 ,abc1 
	 * test_1创建两个ak，test2和abc1各创建一个ak
	 * 用 ak匹配，模糊匹配
	 */
	public void test_listUsers_akMatch2() throws IOException {
		String UserName1="test_1";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName1+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		String userId1=AssertCreateUserResult(resultPair.second(), UserName1, tags);

		// 插入数据库aksk
		AkSkMeta aksk = new AkSkMeta(owner.getId());
        aksk.isRoot = 0;
        aksk.userId = userId1;
        aksk.userName = UserName1;
        aksk.accessKey="abcdefgh";
        aksk.setSecretKey("ccccccccc");
        metaClient.akskInsert(aksk);
        User user1 = new User();
        user1.accountId = "3fdmxmc3pqvmp";
        user1.userName = UserName1;
        user1.accessKeys = new ArrayList<>();
        user1.accessKeys.add(aksk.accessKey);
        
        aksk.accessKey="12345678";
        aksk.setSecretKey("world");
        metaClient.akskInsert(aksk);
        user1.accessKeys.add(aksk.accessKey);
        HBaseUtils.put(user1);
		
		String UserName2="test_2";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName2;
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair2.first().intValue());
		String userId2=AssertCreateUserResult(resultPair2.second(), UserName2, null);
		
		AkSkMeta aksk2 = new AkSkMeta(owner.getId());
        aksk2.isRoot = 0;
        aksk2.userId = userId2;
        aksk2.userName = UserName2;
        aksk2.accessKey="highlmn";
        aksk2.setSecretKey("ffffffffff");
        metaClient.akskInsert(aksk2);
        User user2 = new User();
        user2.accountId = "3fdmxmc3pqvmp";
        user2.userName = UserName1;
        user2.accessKeys = new ArrayList<>();
        user2.userName=UserName2;
        user2.accessKeys.add(aksk2.accessKey);
        HBaseUtils.put(user2);
		
		String UserName3="abc1";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName3;
		Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair3.first().intValue());
		String userId3=AssertCreateUserResult(resultPair3.second(), UserName3, null);
		
		AkSkMeta aksk3 = new AkSkMeta(owner.getId());
		aksk3.isRoot = 0;
		aksk3.userId = userId3;
		aksk3.userName = UserName3;
		aksk3.accessKey="fgh123";
		aksk3.setSecretKey("jjjjjjjjjjjjj");
        metaClient.akskInsert(aksk3);
        
        User user3 = new User();
        user3.accountId = "3fdmxmc3pqvmp";
        user3.userName = UserName1;
        user3.accessKeys = new ArrayList<>();
        user3.userName=UserName3;
        user3.accessKeys.add(aksk3.accessKey);
        HBaseUtils.put(user3);
		
		// list ak匹配
		body="Action=ListUsers&Version=2010-05-08&AccessKeyId=123";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult.first().intValue());
		
		Map<String, Pair<Integer, Integer>> users1Map=new HashMap<String, Pair<Integer,Integer>>();
        Pair<Integer, Integer> user1Pair=new Pair<Integer, Integer>();
        user1Pair.first(2);
        user1Pair.second(0);
        users1Map.put(UserName1, user1Pair);
        Pair<Integer, Integer> user2Pair=new Pair<Integer, Integer>();
        user2Pair.first(1);
        user2Pair.second(0);
        users1Map.put(UserName3, user2Pair);
		AssertlistUsersResult(listresult.second(), users1Map,false);
	}
	
	@Test
	/*
	 * 创建test_1,test_2 ,abc1 
	 * test_1创建两个ak，test2和abc1各创建一个ak
	 * 用 ak匹配，不匹配
	 */
	public void test_listUsers_akMatch3() throws IOException {
		String UserName1="test_1";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName1+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		String userId1=AssertCreateUserResult(resultPair.second(), UserName1, tags);

		// 插入数据库aksk
		AkSkMeta aksk = new AkSkMeta(owner.getId());
        aksk.isRoot = 0;
        aksk.userId = userId1;
        aksk.userName = UserName1;
        aksk.accessKey="abcdefgh";
        aksk.setSecretKey("ccccccccc");
        metaClient.akskInsert(aksk);
        User user1 = new User();
        user1.accountId = "3fdmxmc3pqvmp";
        user1.userName = UserName1;
        user1.accessKeys = new ArrayList<>();
        user1.accessKeys.add(aksk.accessKey);
        
        aksk.accessKey="12345678";
        aksk.setSecretKey("world");
        metaClient.akskInsert(aksk);
        user1.accessKeys.add(aksk.accessKey);
        HBaseUtils.put(user1);
		
		String UserName2="test_2";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName2;
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair2.first().intValue());
		String userId2=AssertCreateUserResult(resultPair2.second(), UserName2, null);
		
		AkSkMeta aksk2 = new AkSkMeta(owner.getId());
        aksk2.isRoot = 0;
        aksk2.userId = userId2;
        aksk2.userName = UserName2;
        aksk2.accessKey="highlmn";
        aksk2.setSecretKey("ffffffffff");
        metaClient.akskInsert(aksk2);
        User user2 = new User();
        user2.accountId = "3fdmxmc3pqvmp";
        user2.userName = UserName1;
        user2.accessKeys = new ArrayList<>();
        user2.userName=UserName2;
        user2.accessKeys.add(aksk2.accessKey);
        HBaseUtils.put(user2);
		
		String UserName3="abc1";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName3;
		Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair3.first().intValue());
		String userId3=AssertCreateUserResult(resultPair3.second(), UserName3, null);
		
		AkSkMeta aksk3 = new AkSkMeta(owner.getId());
		aksk3.isRoot = 0;
		aksk3.userId = userId3;
		aksk3.userName = UserName3;
		aksk3.accessKey="fgh123";
		aksk3.setSecretKey("jjjjjjjjjjjjj");
        metaClient.akskInsert(aksk3);
        
        User user3 = new User();
        user3.accountId = "3fdmxmc3pqvmp";
        user3.userName = UserName1;
        user3.accessKeys = new ArrayList<>();
        user3.userName=UserName3;
        user3.accessKeys.add(aksk3.accessKey);
        HBaseUtils.put(user3);
		
		// list ak匹配
		body="Action=ListUsers&Version=2010-05-08&AccessKeyId=xyz";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult.first().intValue());

		AssertlistUsersResult(listresult.second(), null,false);
		
	}
	
	@Test
	public void test_listUsers_ak0() throws JSONException {
		String body="Action=ListUsers&Version=2010-05-08&AccessKeyId=";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, listresult.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(listresult.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'accessKeyId' is invalid. It must contain only alphanumeric characters", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	
	@Test
	/*
	 * 创建test_1,test_2 ,abc1 
	 * test_1创建两个ak，test2和abc1各创建一个ak
	 * 用username和ak匹配
	 */
	public void test_listUsers_usernameAndakMatch() throws IOException {
		String UserName1="test_1";
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test1@oos.com");
		
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName1+"&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		String userId1=AssertCreateUserResult(resultPair.second(), UserName1, tags);

		// 插入数据库aksk
		AkSkMeta aksk = new AkSkMeta(owner.getId());
        aksk.isRoot = 0;
        aksk.userId = userId1;
        aksk.userName = UserName1;
        aksk.accessKey="abcdefgh";
        aksk.setSecretKey("ccccccccc");
        metaClient.akskInsert(aksk);
        User user1 = new User();
        user1.accountId = "3fdmxmc3pqvmp";
        user1.userName = UserName1;
        user1.accessKeys = new ArrayList<>();
        user1.accessKeys.add(aksk.accessKey);
        
        aksk.accessKey="12345678";
        aksk.setSecretKey("world");
        metaClient.akskInsert(aksk);
        user1.accessKeys.add(aksk.accessKey);
        HBaseUtils.put(user1);
		
		String UserName2="test_2";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName2;
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair2.first().intValue());
		String userId2=AssertCreateUserResult(resultPair2.second(), UserName2, null);
		
		AkSkMeta aksk2 = new AkSkMeta(owner.getId());
        aksk2.isRoot = 0;
        aksk2.userId = userId2;
        aksk2.userName = UserName2;
        aksk2.accessKey="highlmn";
        aksk2.setSecretKey("ffffffffff");
        metaClient.akskInsert(aksk2);
        User user2 = new User();
        user2.accountId = "3fdmxmc3pqvmp";
        user2.userName = UserName1;
        user2.accessKeys = new ArrayList<>();
        user2.userName=UserName2;
        user2.accessKeys.add(aksk2.accessKey);
        HBaseUtils.put(user2);
		
		String UserName3="abc1";
		body="Action=CreateUser&Version=2010-05-08&UserName="+UserName3;
		Pair<Integer, String> resultPair3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair3.first().intValue());
		String userId3=AssertCreateUserResult(resultPair3.second(), UserName3, null);
		
		AkSkMeta aksk3 = new AkSkMeta(owner.getId());
		aksk3.isRoot = 0;
		aksk3.userId = userId3;
		aksk3.userName = UserName3;
		aksk3.accessKey="fgh123";
		aksk3.setSecretKey("jjjjjjjjjjjjj");
        metaClient.akskInsert(aksk3);
        
        User user3 = new User();
        user3.accountId = "3fdmxmc3pqvmp";
        user3.userName = UserName1;
        user3.accessKeys = new ArrayList<>();
        user3.userName=UserName3;
        user3.accessKeys.add(aksk3.accessKey);
        HBaseUtils.put(user3);
		
		// list ak匹配
		body="Action=ListUsers&Version=2010-05-08&AccessKeyId=123&UserName=test";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult.first().intValue());
		
		Map<String, Pair<Integer, Integer>> users1Map=new HashMap<String, Pair<Integer,Integer>>();
        Pair<Integer, Integer> user1Pair=new Pair<Integer, Integer>();
        user1Pair.first(2);
        user1Pair.second(0);
        users1Map.put(UserName1, user1Pair);
		AssertlistUsersResult(listresult.second(), users1Map,false);
		
	}
	
	@Test
	/*
	 * 分页查询 marker参数长度为0
	 */
	public void test_listUsers_Marker0() throws JSONException {
		String body="Action=ListUsers&Version=2010-05-08&Marker=";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, listresult.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(listresult.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'marker' is invalid. It must contain only printable ASCII characters", error.get("Message"));
		assertEquals("/", error.get("Resource"));

	}
	
	
	@Test
	/*
	 * 分页查询maxItems为0
	 */
	public void test_listUsers_MaxItems0() throws JSONException {
		String body="Action=ListUsers&Version=2010-05-08&MaxItems=0";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, listresult.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(listresult.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	
	@Test
	/*
	 * 分页查询maxItems为1000
	 */
	public void test_listUsers_MaxItems1000() throws JSONException {
		String body="Action=ListUsers&Version=2010-05-08&MaxItems=1000";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult.first().intValue());
		
	}
	
	@Test
	/*
	 * 分页查询maxItems超过1000
	 */
	public void test_listUsers_MaxItems1001() throws JSONException {
		String body="Action=ListUsers&Version=2010-05-08&MaxItems=1001";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, listresult.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(listresult.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	

	@Test
	/*
	 * 创建102个用户，默认maxItems为100
	 */
	public void test_listUsers_MaxItems100() {
		
		for (int i = 1; i <= 102; i++) {
		String UserName="test_"+i;
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		}
		String body="Action=ListUsers&Version=2010-05-08";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult.first().intValue());
		
		Map<String, Pair<Integer, Integer>> firstPage=new HashMap<String, Pair<Integer,Integer>>();
        
		for (int i = 1; i <= 102; i++) {
			if (i==98||i==99) {
				continue;
			}else {
				Pair<Integer, Integer> user1Pair=new Pair<Integer, Integer>();
		        user1Pair.first(0);
		        user1Pair.second(0);
		        firstPage.put("test_"+i, user1Pair);
			}
		}
		
		String maker=AssertlistUsersResult(listresult.second(), firstPage, true);
		
		body="Action=ListUsers&Version=2010-05-08&Marker="+maker;
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult2.first().intValue());
		
		Map<String, Pair<Integer, Integer>> secondPage=new HashMap<String, Pair<Integer,Integer>>();
		Pair<Integer, Integer> user1Pair=new Pair<Integer, Integer>();
        user1Pair.first(0);
        user1Pair.second(0);
        secondPage.put("test_98", user1Pair);
        secondPage.put("test_99", user1Pair);
		
		AssertlistUsersResult(listresult2.second(), secondPage, false);
	}
	
	@Test
	/*
	 * 创建102个用户，分页查询 username包含5 maxItems为10
	 */
	public void test_listUsers_MaxItems10username() {
		// 创建102个用户
		for (int i = 1; i <= 102; i++) {
			String UserName="test_"+i;
			String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
			Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
			
			assertEquals(200, resultPair.first().intValue());
			AssertCreateUserResult(resultPair.second(), UserName, null);

		}
		
		String body="Action=ListUsers&Version=2010-05-08&UserName=5&MaxItems=10";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult.first().intValue());
		
		Map<String, Pair<Integer, Integer>> firstPage=new HashMap<String, Pair<Integer,Integer>>();
		Pair<Integer, Integer> user1Pair=new Pair<Integer, Integer>();
        user1Pair.first(0);
        user1Pair.second(0);
		firstPage.put("test_15",user1Pair);
		firstPage.put("test_25",user1Pair);
		firstPage.put("test_35",user1Pair);
		firstPage.put("test_45",user1Pair);
		firstPage.put("test_5",user1Pair);
		firstPage.put("test_50",user1Pair);
		firstPage.put("test_51",user1Pair);
		firstPage.put("test_52",user1Pair);
		firstPage.put("test_53",user1Pair);
		firstPage.put("test_54",user1Pair);
		String maker=AssertlistUsersResult(listresult.second(), firstPage, true);
		
		body="Action=ListUsers&Version=2010-05-08&UserName=5&MaxItems=10&Marker="+maker;
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult2.first().intValue());
		
		Map<String, Pair<Integer, Integer>> secondPage=new HashMap<String, Pair<Integer,Integer>>();
		secondPage.put("test_55",user1Pair);
		secondPage.put("test_56",user1Pair);
		secondPage.put("test_57",user1Pair);
		secondPage.put("test_58",user1Pair);
		secondPage.put("test_59",user1Pair);
		secondPage.put("test_65",user1Pair);
		secondPage.put("test_75",user1Pair);
		secondPage.put("test_85",user1Pair);
		secondPage.put("test_95",user1Pair);
		
		AssertlistUsersResult(listresult2.second(), secondPage, false);
	}
	
	@Test
	/*
	 * 创建102个用户，分页查询 username包含5， ak包含a maxItems为5
	 */
	public void test_listUsers_MaxItems5usernameAndak() throws IOException {
		for (int i = 1; i <= 102; i++) {
			String UserName="test_"+i;
			String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
			Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
			
			assertEquals(200, resultPair.first().intValue());
			String userId=AssertCreateUserResult(resultPair.second(), UserName, null);
			
			// 插入数据库aksk
			AkSkMeta aksk = new AkSkMeta(owner.getId());
	        aksk.isRoot = 0;
	        aksk.userId = userId;
	        aksk.userName = UserName;
	        String s="";
	        if (i%3==0) {
				s="a";
			}else if (i%3==1) {
				s="b";
			}else {
				s="c";
			}
	        aksk.accessKey="test"+i+s;
	        aksk.setSecretKey("ccccccccc");
	        metaClient.akskInsert(aksk);
	        User user1 = new User();
	        user1.accountId = "3fdmxmc3pqvmp";
	        user1.userName = UserName;
	        user1.accessKeys = new ArrayList<>();
	        user1.accessKeys.add(aksk.accessKey);
	        
	        HBaseUtils.put(user1);
		}
		
		String body="Action=ListUsers&Version=2010-05-08&UserName=5&MaxItems=5&AccessKeyId=a";
		Pair<Integer, String> listresult=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult.first().intValue());
		Map<String, Pair<Integer, Integer>> firstPage=new HashMap<String, Pair<Integer,Integer>>();
        Pair<Integer, Integer> user1Pair=new Pair<Integer, Integer>();
        user1Pair.first(1);
        user1Pair.second(0);
		firstPage.put("test_15",user1Pair);
		firstPage.put("test_45",user1Pair);
		firstPage.put("test_51",user1Pair);
		firstPage.put("test_54",user1Pair);
		firstPage.put("test_57",user1Pair);
		
		String marker=AssertlistUsersResult(listresult.second(), firstPage, true);
		body="Action=ListUsers&Version=2010-05-08&UserName=5&MaxItems=5&AccessKeyId=a&Marker="+marker;
		Pair<Integer, String> listresult2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listresult2.first().intValue());
		
		Map<String, Pair<Integer, Integer>> secondPage=new HashMap<String, Pair<Integer,Integer>>();
		secondPage.put("test_75",user1Pair);
		AssertlistUsersResult(listresult2.second(), secondPage, false);
	}
	
	@Test
	/*
	 * 向IAM用户添加tag
	 */
	public void test_TagUser() {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("a");
		tag.second("b");
		String tagString="&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag.first().intValue());
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertListTags(listTag.second(), tags, false);

	}
	@Test
	/*
	 * 没有username在数据库中不存在
	 */
	public void test_TagUser_NoUsername() throws JSONException {
		String UserName="subuser_test1100";
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("a");
		tag.second("b");
		String tagString="&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		String body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, addTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name subuser_test1100 cannot be found.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 向IAM用户添加tag,没有Tags.member.1.Key的参数
	 */
	public void test_TagUser_noKeyParam() throws JSONException {
		String UserName="subuser_test12";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("a");
		tag.second("b");
		String tagString="&Tags.member.1.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, addTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'tags.1.member.key' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 向IAM用户添加tag,Tags.member.1.Key为空
	 */
	public void test_TagUser_Key0Charater() throws JSONException {
		String UserName="subuser_test12";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("a");
		tag.second("b");
		String tagString="&Tags.member.1.Key=&Tags.member.1.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, addTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '' at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}

	@Test
	/*
	 * 向IAM用户添加tag,Tags.member.1.Key字符为128
	 */
	public void test_TagUser_Key128Charater() {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678");
		tag.second("b");
		String tagString="&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag.first().intValue());
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertListTags(listTag.second(), tags, false);
	}
	
	@Test
	/*
	 * 向IAM用户添加tag,Tags.member.1.Key字符为129
	 */
	public void test_TagUser_Key129Charater() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789");
		tag.second("b");
		String tagString="&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, addTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789' at 'tags.1.member.key' failed to satisfy constraint: Member must have length less than or equal to 128", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
		
	}

	@Test
	/*
	 * 向IAM用户添加tag,Tags.member.1.Key包含特殊字符
	 * _.:/=+-@
	 */
	public void test_TagUser_KeyHasSpecialCharater() {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("yan_xiao.1111@163.com+user=/test:test-1");
		tag.second("b");
		String tagString="&Tags.member.1.Key="+UrlEncoded.encodeString(tag.first())+"&Tags.member.1.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag.first().intValue());
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertListTags(listTag.second(), tags, false);
	}
	
	@Test
	/*
	 * 向IAM用户添加tag,Tags.member.1.Key包含特殊字符
	 * 不在_.:/=+-@范围
	 */
	public void test_TagUser_KeyHasSpecialCharater2() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("yan_xiao.1111@163.com#user=/test:test-1");
		tag.second("b");
		String tagString="&Tags.member.1.Key="+UrlEncoded.encodeString(tag.first())+"&Tags.member.1.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, addTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value 'yan_xiao.1111@163.com#user=/test:test-1' at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
		
	}
	
	@Test
	/*
	 * 向IAM用户添加tag,没有Tags.member.1.Value的参数
	 */
	public void test_TagUser_noValueParam() throws JSONException {
		String UserName="subuser_test12";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("a");
		tag.second("b");
		String tagString="&Tags.member.1.Key="+tag.first();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, addTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'tags.1.member.value' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 向IAM用户添加tag,Tags.member.1.Value为空
	 */
	public void test_TagUser_Value0Charater() throws JSONException {
		String UserName="subuser_test12";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("a");
		tag.second("");
		String tagString="&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag.first().intValue());
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertListTags(listTag.second(), tags, false);
	}
	
	
	@Test
	/*
	 * 向IAM用户添加tag,Tags.member.1.Value字符为256
	 */
	public void test_TagUser_Value256Charater() {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("a");
		tag.second("1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456");
		String tagString="&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag.first().intValue());
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertListTags(listTag.second(), tags, false);
	}
	
	@Test
	/*
	 * 向IAM用户添加tag,Tags.member.1.Value字符为257
	 */
	public void test_TagUser_Value257Charater() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("a");
		tag.second("12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567");
		String tagString="&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, addTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567' at 'tags.1.member.value' failed to satisfy constraint: Member must have length less than or equal to 256", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}

	@Test
	/*
	 * 向IAM用户添加tag,Tags.member.1.Value包含特殊字符
	 * _.:/=+-@
	 */
	public void test_TagUser_ValueHasSpecialCharater() {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("yan_xiao.1111@163.com+user=/test:test-1");
		tag.second("b:lal-1+2=3/test@4.56_");
		String tagString="&Tags.member.1.Key="+UrlEncoded.encodeString(tag.first())+"&Tags.member.1.Value="+UrlEncoded.encodeString(tag.second());
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag.first().intValue());
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertListTags(listTag.second(), tags, false);
	}
	
	@Test
	/*
	 * 向IAM用户添加tag,Tags.member.1.Value包含特殊字符
	 * 不在_.:/=+-@范围
	 */
	public void test_TagUser_ValueHasSpecialCharater2() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("yan_xiao.1111@163.com#user=/test:test-1");
		tag.second("$179&");
		String tagString="&Tags.member.1.Key="+UrlEncoded.encodeString(tag.first())+"&Tags.member.1.Value="+UrlEncoded.encodeString(tag.second());
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, addTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("2 validation errors detected: Value 'yan_xiao.1111@163.com#user=/test:test-1' at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+; Value '$179&' at 'tags.1.member.value' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 一次添加两个相同key的标签,大小写不一致
	 */
	public void test_TagUser_addTwoSameKey() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag1=new Pair<String, String>();
		tag1.first("phone");
		tag1.second("12345678901");
		Pair<String, String> tag2=new Pair<String, String>();
		tag2.first("Phone");
		tag2.second("19913145224");
		
		String tagString="&Tags.member.1.Key="+tag1.first()+"&Tags.member.1.Value="+tag1.second()+"&Tags.member.2.Key="+tag2.first()+"&Tags.member.2.Value="+tag2.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, addTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag.second());
		assertEquals("InvalidInput", error.get("Code"));
		assertEquals("Duplicate tag keys found. Please note that Tag keys are case insensitive.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 两次添加两个相同Key的标签
	 */
	public void test_TagUser_addTwoSameKey2() {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag1=new Pair<String, String>();
		tag1.first("phone");
		tag1.second("12345678901");
		String tagString="&Tags.member.1.Key="+tag1.first()+"&Tags.member.1.Value="+tag1.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag.first().intValue());
		
		Pair<String, String> tag2=new Pair<String, String>();
		tag2.first("PHONE");
		tag2.second("19913145224");
		tagString="&Tags.member.1.Key="+tag2.first()+"&Tags.member.1.Value="+tag2.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag2.first().intValue());
		

		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag2);
		AssertListTags(listTag.second(), tags, false);
	}
	
	@Test
	/*
	 * 两次添加两个相同Key的标签.第二次从Tags.member.2.key开始
	 */
	public void test_TagUser_addTwoSameKey3() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag1=new Pair<String, String>();
		tag1.first("phone");
		tag1.second("12345678901");
		String tagString="&Tags.member.1.Key="+tag1.first()+"&Tags.member.1.Value="+tag1.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag.first().intValue());
		
		Pair<String, String> tag2=new Pair<String, String>();
		tag2.first("PHONE");
		tag2.second("19913145224");
		tagString="&Tags.member.2.Key="+tag2.first()+"&Tags.member.2.Value="+tag2.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, addTag2.first().intValue());
		
		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag2.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("2 validation errors detected: Value null at 'tags.1.member.key' failed to satisfy constraint: Member must not be null; Value null at 'tags.1.member.value' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 从Tags.member.3.Key开始设置标签
	 */
	public void test_TagUser_addKeyfrom3() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("a");
		tag.second("b");
		String tagString="&Tags.member.3.Key="+tag.first()+"&Tags.member.3.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, addTag.first().intValue());
		
		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("4 validation errors detected: Value null at 'tags.1.member.key' failed to satisfy constraint: Member must not be null; Value null at 'tags.1.member.value' failed to satisfy constraint: Member must not be null; Value null at 'tags.2.member.key' failed to satisfy constraint: Member must not be null; Value null at 'tags.2.member.value' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 从Tags.member.0.Key开始设置标签
	 */
	public void test_TagUser_addKeyfrom0() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("a");
		tag.second("b");
		String tagString="&Tags.member.0.Key="+tag.first()+"&Tags.member.0.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, addTag.first().intValue());
		
		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag.second());
		assertEquals("MalformedInput", error.get("Code"));
		assertEquals("0 is not a valid index.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 添加标签超过10
	 */
	public void test_TagUser_addKeymoreThan10() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		
		String tagString="";
		for (int i = 1; i <= 10; i++) {
			Pair<String, String> tag=new Pair<String, String>();
			tag.first("key_"+i);
			tag.second("value_"+i);
			tags.add(tag);
			tagString+="&Tags.member."+i+".Key="+tag.first()+"&Tags.member."+i+".Value="+tag.second();
		}
		System.out.println(tagString);
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag.first().intValue());
		
		tagString="&Tags.member.1.Key=key_11&Tags.member.1.Value=value_11";
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409, addTag2.first().intValue());
		
		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag2.second());
		assertEquals("LimitExceeded", error.get("Code"));
		assertEquals("The number of tags has reached the maximum limit.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 添加标签超过10,标签Tags.member.11.Key
	 */
	public void test_TagUser_addKeymoreThan10_2() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		
		String tagString="";
		for (int i = 1; i <= 11; i++) {
			Pair<String, String> tag=new Pair<String, String>();
			tag.first("key_"+i);
			tag.second("value_"+i);
			tags.add(tag);
			tagString+="&Tags.member."+i+".Key="+tag.first()+"&Tags.member."+i+".Value="+tag.second();
		}
		System.out.println(tagString);
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, addTag.first().intValue());

		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag.second());
		assertEquals("MalformedInput", error.get("Code"));
		assertEquals("11 is not a valid index.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 去掉标签
	 */
	public void test_UntagUser() {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("a");
		tag.second("b");
		String tagString="&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag.first().intValue());
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertListTags(listTag.second(), tags, false);
		
		String untagString="&TagKeys.member.1="+tag.first();
		body="Action=UntagUser&Version=2010-05-08&UserName="+UserName+untagString;
		Pair<Integer, String> unTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, unTag.first().intValue());
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> listTag2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag2.first().intValue());
		AssertListTags(listTag2.second(), null, false);
	}
	
	@Test
    /*
     * 去掉标签去掉其中一个
     */
    public void test_UntagUser_oneof() {
        String UserName="subuser_test11";
        String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        AssertCreateUserResult(resultPair.second(), UserName, null);
        
        Pair<String, String> tag=new Pair<String, String>();
        tag.first("a");
        tag.second("1");
        Pair<String, String> tag2=new Pair<String, String>();
        tag2.first("b");
        tag2.second("2");
        String tagString="&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second()+"&Tags.member.2.Key="+tag2.first()+"&Tags.member.2.Value="+tag2.second();
        body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
        Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, addTag.first().intValue());
        
        body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
        Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, listTag.first().intValue());
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        tags.add(tag);
        tags.add(tag2);
        AssertListTags(listTag.second(), tags, false);
        
        String untagString="&TagKeys.member.1="+tag.first();
        body="Action=UntagUser&Version=2010-05-08&UserName="+UserName+untagString;
        Pair<Integer, String> unTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, unTag.first().intValue());
        
        body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
        Pair<Integer, String> listTag2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, listTag2.first().intValue());
        List<Pair<String, String>> tags2= new ArrayList<Pair<String,String>>();
        tags2.add(tag2);
        AssertListTags(listTag2.second(), tags2, false);
    }
	
	@Test
    /*
     * 去掉标签去掉其中两个
     */
    public void test_UntagUser_twoOfThree() {
        String UserName="subuser_test11";
        String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, resultPair.first().intValue());
        AssertCreateUserResult(resultPair.second(), UserName, null);
        
        Pair<String, String> tag=new Pair<String, String>();
        tag.first("a");
        tag.second("1");
        Pair<String, String> tag2=new Pair<String, String>();
        tag2.first("b");
        tag2.second("2");
        Pair<String, String> tag3=new Pair<String, String>();
        tag3.first("c");
        tag3.second("3");
        String tagString="&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second()+"&Tags.member.2.Key="+tag2.first()+"&Tags.member.2.Value="+tag2.second()+"&Tags.member.3.Key="+tag3.first()+"&Tags.member.3.Value="+tag3.second();
        body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
        Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, addTag.first().intValue());
        
        body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
        Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, listTag.first().intValue());
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        tags.add(tag);
        tags.add(tag2);
        AssertListTags(listTag.second(), tags, false);
        
        String untagString="&TagKeys.member.1="+tag.first()+"&TagKeys.member.2="+tag2.first();
        body="Action=UntagUser&Version=2010-05-08&UserName="+UserName+untagString;
        Pair<Integer, String> unTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, unTag.first().intValue());
        
        body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
        Pair<Integer, String> listTag2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, listTag2.first().intValue());
        List<Pair<String, String>> tags2= new ArrayList<Pair<String,String>>();
        tags2.add(tag3);
        AssertListTags(listTag2.second(), tags2, false);
    }
	
	@Test
	/*
	 * username参数不存在
	 */
	public void test_UntagUser_noUserNameParam() throws JSONException {
		
		String untagString="&TagKeys.member.1=a";
		String body="Action=UntagUser&Version=2010-05-08"+untagString;
		Pair<Integer, String> unTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, unTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(unTag.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * username在数据库中不存在
	 */
	public void test_UntagUser_noUserName() throws JSONException {
		String UserName="nouser";
		String untagString="&TagKeys.member.1=a";
		String body="Action=UntagUser&Version=2010-05-08&UserName="+UserName+untagString;
		Pair<Integer, String> unTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, unTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(unTag.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name nouser cannot be found.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * Tags.member.N在数据库中不存在
	 */
	public void test_UntagUser_noN(){
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("a");
		tag.second("b");
		String tagString="&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag.first().intValue());
		
		String untagString="&TagKeys.member.1=123";
		body="Action=UntagUser&Version=2010-05-08&UserName="+UserName+untagString;
		Pair<Integer, String> unTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, unTag.first().intValue());
	}
	
	@Test
	/*
	 * Tags.member.0
	 */
	public void test_UntagUser_N0() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		String untagString="&TagKeys.member.0=123";
		body="Action=UntagUser&Version=2010-05-08&UserName="+UserName+untagString;
		Pair<Integer, String> unTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, unTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(unTag.second());
		assertEquals("MalformedInput", error.get("Code"));
		assertEquals("0 is not a valid index.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * Tags.member.11
	 */
	public void test_UntagUser_N11() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		String untagString="&TagKeys.member.11=123";
		body="Action=UntagUser&Version=2010-05-08&UserName="+UserName+untagString;
		Pair<Integer, String> unTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, unTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(unTag.second());
		assertEquals("MalformedInput", error.get("Code"));
		assertEquals("11 is not a valid index.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * TagKeys.member.1有两个
	 */
	public void test_UntagUser_sameN() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("a");
		tag.second("b");
		String tagString="&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag.first().intValue());
		
		String untagString="&TagKeys.member.1=123&TagKeys.member.1=a";
		body="Action=UntagUser&Version=2010-05-08&UserName="+UserName+untagString;
		Pair<Integer, String> unTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, unTag.first().intValue());
	}
	
	@Test
	/*
	 * 中间有重复,重复tag覆盖
	 */
	public void test_UntagUser_NmoreThan10() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		String untagString="&TagKeys.member.3=123";
		for (int i = 1; i <= 10; i++) {
			untagString+="&TagKeys.member."+i+"=key_"+i;
		}
		
		System.out.println(untagString);
		
		body="Action=UntagUser&Version=2010-05-08&UserName="+UserName+untagString;
		Pair<Integer, String> unTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, unTag.first().intValue());
	}
	
	@Test
	/*
	 * 向IAM用户添加tag,Tags.member.1.Key包含特殊字符
	 * _.:/=+-@
	 * 删除
	 */
	public void test_UntagUser_KeyHasSpecialCharater() {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("yan_xiao.1111@163.com:user=/test:test-1");
		tag.second("b");
		String tagString="&Tags.member.1.Key="+UrlEncoded.encodeString(tag.first())+"&Tags.member.1.Value="+tag.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag.first().intValue());
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		AssertListTags(listTag.second(), tags, false);
		
		String untagString="&TagKeys.member.1="+tag.first();
		body="Action=UntagUser&Version=2010-05-08&UserName="+UserName+untagString;
		Pair<Integer, String> unTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, unTag.first().intValue());
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> listTag2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag2.first().intValue());
		AssertListTags(listTag.second(), null, false);
	}
	

	@Test
	/*
	 * 添加标签并list
	 */
	public void test_listTags() {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		Pair<String, String> tag=new Pair<String, String>();
		tag.first("email");
		tag.second("test@oos.com");
		Pair<String, String> tag2=new Pair<String, String>();
		tag2.first("phone");
		tag2.second("12345678901");
		String tagString="&Tags.member.1.Key="+tag.first()+"&Tags.member.1.Value="+tag.second()+"&Tags.member.2.Key="+tag2.first()+"&Tags.member.2.Value="+tag2.second();
		body="Action=TagUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addTag.first().intValue());
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag.first().intValue());
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		tags.add(tag);
		tags.add(tag2);
		AssertListTags(listTag.second(), tags, false);
	}
	
	@Test
	/*
	 * 没有userNameParam
	 */
	public void test_listTags_noUserNameParam() throws JSONException {
		String body="Action=ListUserTags&Version=2010-05-08";
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, listTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(listTag.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * username在数据库中不存在
	 */
	public void test_listTags_NoUsername() throws JSONException {
		String UserName="nouser";
		String body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> addTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, addTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(addTag.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name nouser cannot be found.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * Marker设置为空
	 */
	public void test_listTags_Marker0() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName+"&Marker=";
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, listTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(listTag.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'marker' is invalid. It must contain only printable ASCII characters", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
		
	}
	
	@Test
	/*
	 * MaxItems=0
	 */
	public void test_listTags_MaxItems0() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName+"&MaxItems=0";
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, listTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(listTag.second());
		
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * MaxItems=1000
	 */
	public void test_listTags_MaxItems1000() {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName+"&MaxItems=1000";
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag.first().intValue());
	}
	
	@Test
	/*
	 * MaxItems=1001
	 */
	public void test_listTags_MaxItems1001() throws JSONException {
		String UserName="subuser_test11";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, null);
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName+"&MaxItems=1001";
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, listTag.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(listTag.second());
		
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 给用户添加9个标签
	 */
	public void test_listTags_MaxItems5() {
		String UserName="subuser_test11";
		
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		String tagString="";
		for (int i = 1; i < 10; i++) {
			Pair<String, String> tag=new Pair<String, String>();
			tag.first("key_"+((char) (65+i-1)));
			tag.second("value_"+((char) (65+i-1)));
			tags.add(tag);
			tagString+="&Tags.member."+i+".Key="+tag.first()+"&Tags.member."+i+".Value="+tag.second();
		}
		System.out.println(tagString);
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, tags);
		
		List<Pair<String, String>> tags1= new ArrayList<Pair<String,String>>();
		for (int i = 1; i <=5; i++) {
			Pair<String, String> tag=new Pair<String, String>();
			tag.first("key_"+((char) (65+i-1)));
			tag.second("value_"+((char) (65+i-1)));
			tags1.add(tag);
		}
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName+"&MaxItems=5";
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag.first().intValue());
		String marker=AssertListTags(listTag.second(), tags1, true);
		
		List<Pair<String, String>> tags2= new ArrayList<Pair<String,String>>();
		for (int i = 6; i <10; i++) {
			Pair<String, String> tag=new Pair<String, String>();
			tag.first("key_"+((char) (65+i-1)));
			tag.second("value_"+((char) (65+i-1)));
			tags2.add(tag);
		}
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName+"&MaxItems=5&Marker="+marker;
		Pair<Integer, String> listTag2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag2.first().intValue());
		AssertListTags(listTag2.second(), tags2, false);
		
	}
	
	@Test
	/*
	 * 给用户添加10个标签，MaxItems默认
	 */
	public void test_listTags_MaxItems() {
		String UserName="subuser_test11";
		List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
		String tagString="";
		for (int i = 1; i <=5; i++) {
			Pair<String, String> tag=new Pair<String, String>();
			tag.first("key_"+((char) (65+i-1))+1);
			tag.second("value_"+((char) (65+i-1))+1);
			Pair<String, String> tag2=new Pair<String, String>();
			tag2.first("key_"+((char) (65+i-1))+2);
			tag2.second("value_"+((char) (65+i-1))+2);
			tags.add(tag);
			tags.add(tag2);
			tagString+="&Tags.member."+(2*i-1)+".Key="+tag.first()+"&Tags.member."+(2*i-1)+".Value="+tag.second()+"&Tags.member."+(i*2)+".Key="+tag2.first()+"&Tags.member."+(i*2)+".Value="+tag2.second();
		}
		System.out.println(tagString);
		String body="Action=CreateUser&Version=2010-05-08&UserName="+UserName+tagString;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), UserName, tags);
		
		body="Action=ListUserTags&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> listTag=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, listTag.first().intValue());
		AssertListTags(listTag.second(), tags, false);
	}
	
	@Test
	/*
	 * 给用户添加组，并list
	 */
	public void test_ListGroupsForUser() {
		IAMTestUtils.TrancateTable(IAMTestUtils.iamGroupTable);
		// 创建用户
		String userName="subuser_test21";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		// 创建组
		String groupName1="yxgroup1";
		String groupName2="yxgroup2";
		body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName1;
		Pair<Integer, String> group1=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, group1.first().intValue());
		
		body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName2;
		Pair<Integer, String> group2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, group2.first().intValue());
		
		// 给用户添加组
		body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName1+"&UserName="+userName;
		Pair<Integer, String> addToGroup=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addToGroup.first().intValue());
		
		body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName2+"&UserName="+userName;
		Pair<Integer, String> addToGroup2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, addToGroup2.first().intValue());
		
		// list
		body="Action=ListGroupsForUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list.first().intValue());
		List<String> groups=new ArrayList<String>();
		groups.add(groupName1);
		groups.add(groupName2);
		AssertlistGroupForUser(list.second(), groups, false);
		
	}
	
	@Test
	/*
	 * 没有userNameParam
	 */
	public void test_ListGroupsForUser_noUserNameParam() throws JSONException {
		
		String body="Action=ListGroupsForUser&Version=2010-05-08";
		Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, list.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(list.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * username在数据库中不存在
	 */
	public void test_ListGroupsForUser_NoUsername() throws JSONException {
		String UserName="nouser";
		String body="Action=ListGroupsForUser&Version=2010-05-08&UserName="+UserName;
		Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, list.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(list.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name nouser cannot be found.", error.get("Message"));
		assertEquals(UserName, error.get("Resource"));
	}
	
	@Test
	/*
	 * Marker设置为空
	 */
	public void test_ListGroupsForUser_Marker0() throws JSONException {
		String userName="subuser_test21";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=ListGroupsForUser&Version=2010-05-08&UserName="+userName+"&Marker=";
		Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, list.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(list.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'marker' is invalid. It must contain only printable ASCII characters", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * MaxItems=0
	 */
	public void test_ListGroupsForUser_MaxItems0() throws JSONException {
		String userName="subuser_test21";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=ListGroupsForUser&Version=2010-05-08&UserName="+userName+"&MaxItems=0";
		Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, list.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(list.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * MaxItems=1000
	 */
	public void test_ListGroupsForUser_MaxItems1000() {
		String userName="subuser_test21";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=ListGroupsForUser&Version=2010-05-08&UserName="+userName+"&MaxItems=1000";
		Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list.first().intValue());
	}
	
	@Test
	/*
	 * MaxItems=1001
	 */
	public void test_ListGroupsForUser_MaxItems1001() throws JSONException {
		String userName="subuser_test21";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=ListGroupsForUser&Version=2010-05-08&UserName="+userName+"&MaxItems=1001";
		Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, list.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(list.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 给用户添加10个组
	 */
	public void test_ListGroupsForUser_MaxItems6() {
		IAMTestUtils.TrancateTable(IAMTestUtils.iamGroupTable);
		// 创建用户
		String userName="subuser_test21";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);

		for (int i = 1; i <= 10; i++) {
			// 创建组
			String groupName="group_"+((char) (65+i-1));
			body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
			Pair<Integer, String> group1=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
			assertEquals(200, group1.first().intValue());
			
			// 给用户添加组
			body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+userName;
			Pair<Integer, String> addToGroup=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
			assertEquals(200, addToGroup.first().intValue());
			
		}
	
		// list
		body="Action=ListGroupsForUser&Version=2010-05-08&UserName="+userName+"&MaxItems=6";
		Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list.first().intValue());
		List<String> groups1=new ArrayList<String>();
		for (int i = 1; i <= 6; i++) {
			String groupName="group_"+((char) (65+i-1));
			groups1.add(groupName);
		}
		String marker=AssertlistGroupForUser(list.second(), groups1, true);
		
		body="Action=ListGroupsForUser&Version=2010-05-08&UserName="+userName+"&MaxItems=6&Marker="+marker;
		Pair<Integer, String> list2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list2.first().intValue());
		List<String> groups2=new ArrayList<String>();
		for (int i = 6; i <= 10; i++) {
			String groupName="group_"+((char) (65+i-1));
			groups2.add(groupName);
		}
		AssertlistGroupForUser(list2.second(), groups2, false);
		
	}
	
	@Test
	/*
	 * 给用户添加10个组,MaxItems默认
	 */
	public void test_ListGroupsForUser_MaxItems() {
		IAMTestUtils.TrancateTable(IAMTestUtils.iamGroupTable);
		// 创建用户
		String userName="subuser_test21";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		List<String> groups=new ArrayList<String>();
		for (int i = 1; i <= 10; i++) {
			// 创建组
			String groupName="group_"+((char) (65+i-1));
			body="Action=CreateGroup&Version=2010-05-08&GroupName="+groupName;
			Pair<Integer, String> group1=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
			assertEquals(200, group1.first().intValue());
			
			// 给用户添加组
			body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+groupName+"&UserName="+userName;
			Pair<Integer, String> addToGroup=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
			assertEquals(200, addToGroup.first().intValue());
			groups.add(groupName);
		}
		
		body="Action=ListGroupsForUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> list=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, list.first().intValue());
		
		AssertlistGroupForUser(list.second(), groups, false);
	}
	
	@Test
	public void test_createLoginProfile() {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
	}
	
	@Test
	/*
	 * 只有数字
	 */
	public void test_createLoginProfile_onlyNum() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, createPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(createPasswd.second());
		assertEquals("PasswordPolicyViolation", error.get("Code"));
		assertEquals("Password does not conform to the account password policy.", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 只有小写字母
	 */
	public void test_createLoginProfile_onlylowerAlp() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=abcdefghi";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, createPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(createPasswd.second());
		assertEquals("PasswordPolicyViolation", error.get("Code"));
		assertEquals("Password does not conform to the account password policy.", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 只有大写字母
	 */
	public void test_createLoginProfile_onlyUpAlp() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=ABCDEFGHIJK";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, createPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(createPasswd.second());
		assertEquals("PasswordPolicyViolation", error.get("Code"));
		assertEquals("Password does not conform to the account password policy.", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 只有大小写字母
	 */
	public void test_createLoginProfile_onlyAlp() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=AbCdEfGhi";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, createPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(createPasswd.second());
		assertEquals("PasswordPolicyViolation", error.get("Code"));
		assertEquals("Password does not conform to the account password policy.", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 只有大写字母和数字
	 */
	public void test_createLoginProfile_onlyAlpandNum() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=A12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, createPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(createPasswd.second());
		assertEquals("PasswordPolicyViolation", error.get("Code"));
		assertEquals("Password does not conform to the account password policy.", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 没有username参数
	 */
	public void test_createLoginProfile_NoUserNameParam() throws JSONException {
		String body="Action=CreateLoginProfile&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, createPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(createPasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * username在数据库不存在
	 */
	public void test_createLoginProfile_NoUserName() throws JSONException {
		String userName="nouser";
		String body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, createPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(createPasswd.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name nouser cannot be found.", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 没有password参数
	 */
	public void test_createLoginProfile_NoPasswordParam() throws JSONException {
		String userName="subuser_test31";

		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName;
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, createPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(createPasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'password' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * password为0位
	 */
	public void test_createLoginProfile_Password0Charater() throws JSONException {
		String userName="subuser_test31";

		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, createPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(createPasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("2 validation errors detected: Value '' at 'password' failed to satisfy constraint: Member must have length greater than or equal to 8; Value at 'password' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\u0009\\u000A\\u000D\\u0020-\\u00FF]+", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * password不够8位
	 */
	public void test_createLoginProfile_Password7Charater() throws JSONException {
		String userName="subuser_test31";

		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a234567";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, createPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(createPasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value 'a234567' at 'password' failed to satisfy constraint: Member must have length greater than or equal to 8", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * password设置128位
	 */
	public void test_createLoginProfile_Password128Charater() {
		String userName="subuser_test31";

		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a2345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		}
	
	@Test
	/*
	 * password超过128位
	 */
	public void test_createLoginProfile_Password129Charater() throws JSONException {
		String userName="subuser_test31";

		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a23456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, createPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(createPasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value 'a23456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789' at 'password' failed to satisfy constraint: Member must have length less than or equal to 128", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 包含特殊字符
	 */
	public void test_createLoginProfile_SpecialCharater() {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password="+UrlEncoded.encodeString("test123@OOS#com");
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		
	}
	
	@Test
	/*
	 * 设置两遍passwd
	 */
	public void test_createLoginProfile_hasPasswd() throws JSONException {
		String userName="subuser_test31";

		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=b12345678";
		Pair<Integer, String> createPasswd2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(409, createPasswd2.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(createPasswd2.second());
		assertEquals("EntityAlreadyExists", error.get("Code"));
		assertEquals("Login Profile for user subuser_test31 already exists.", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * PasswordResetRequired true
	 */
	public void test_createLoginProfile_PasswordResetRequiredTrue() {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678&PasswordResetRequired=true";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, true);
	}
	
	@Test
	/*
	 * PasswordResetRequired false
	 */
	public void test_createLoginProfile_PasswordResetRequiredfalse() {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678&PasswordResetRequired=false";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
	}
	
	@Test
	/*
	 * PasswordResetRequired 非true和false
	 */
	public void test_createLoginProfile_PasswordResetRequiredNotBool() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678&PasswordResetRequired=fa";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, createPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(createPasswd.second());
		assertEquals("MalformedInput", error.get("Code"));
		assertEquals("Invalid Argument.", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	public void test_createLoginProfile_SetpasswdPolicy_MinimumPasswordLength() {
	    IAMTestUtils.TrancateTable("iam-passwordPolicy-yx");
	    String userName="subuser_test31";
        String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        assertEquals(200, resultPair.first().intValue());
        AssertCreateUserResult(resultPair.second(), userName, null);
        
        String bodyPasswd="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&MinimumPasswordLength=10";
        Pair<Integer, String> passwdPolicy=IAMTestUtils.invokeHttpsRequest(bodyPasswd, accessKey, secretKey);
        assertEquals(200, passwdPolicy.first().intValue()); 
        
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
        Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, createPasswd.first().intValue());
        
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=a123456789";
        Pair<Integer, String> createPasswd2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, createPasswd2.first().intValue());
        AssertCreateLoginProfile(createPasswd2.second(), userName, false);
    }
	
	@Test
    public void test_createLoginProfile_SetpasswdPolicy_LowercaseCharacters() {
	    IAMTestUtils.TrancateTable("iam-passwordPolicy-yx");
        String userName="subuser_test32";
        String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        assertEquals(200, resultPair.first().intValue());
        AssertCreateUserResult(resultPair.second(), userName, null);
        
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=1234567890";
        Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, createPasswd.first().intValue());
        
        String bodyPasswd="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireLowercaseCharacters=false";
        Pair<Integer, String> passwdPolicy=IAMTestUtils.invokeHttpsRequest(bodyPasswd, accessKey, secretKey);
        assertEquals(200, passwdPolicy.first().intValue()); 
           
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=1234567890";
        Pair<Integer, String> createPasswd2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, createPasswd2.first().intValue());
        AssertCreateLoginProfile(createPasswd2.second(), userName, false);
    }
	
	@Test
    public void test_createLoginProfile_SetpasswdPolicy_Numbers() {
	    IAMTestUtils.TrancateTable("iam-passwordPolicy-yx");
        String userName="subuser_test33";
        String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        assertEquals(200, resultPair.first().intValue());
        AssertCreateUserResult(resultPair.second(), userName, null);
        
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=abcdefghij";
        Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, createPasswd.first().intValue());
        
        String bodyPasswd="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireNumbers=false";
        Pair<Integer, String> passwdPolicy=IAMTestUtils.invokeHttpsRequest(bodyPasswd, accessKey, secretKey);
        assertEquals(200, passwdPolicy.first().intValue()); 
           
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=abcdefghij";
        Pair<Integer, String> createPasswd2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, createPasswd2.first().intValue());
        AssertCreateLoginProfile(createPasswd2.second(), userName, false);
    }
	
	@Test
    public void test_createLoginProfile_SetpasswdPolicy_Symbols() {
	    IAMTestUtils.TrancateTable("iam-passwordPolicy-yx");
        String userName="subuser_test34";
        String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        assertEquals(200, resultPair.first().intValue());
        AssertCreateUserResult(resultPair.second(), userName, null);
        
        String bodyPasswd="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireSymbols=true";
        Pair<Integer, String> passwdPolicy=IAMTestUtils.invokeHttpsRequest(bodyPasswd, accessKey, secretKey);
        assertEquals(200, passwdPolicy.first().intValue()); 
        
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=abcde12345";
        Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, createPasswd.first().intValue());
           
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=abcde12345$";
        Pair<Integer, String> createPasswd2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, createPasswd2.first().intValue());
        AssertCreateLoginProfile(createPasswd2.second(), userName, false);
    }
	
	
	
	@Test
    public void test_createLoginProfile_SetpasswdPolicy_UppercaseCharacters() {
        IAMTestUtils.TrancateTable("iam-passwordPolicy-yx");
        String userName="subuser_test35";
        String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        assertEquals(200, resultPair.first().intValue());
        AssertCreateUserResult(resultPair.second(), userName, null);
        
        String bodyPasswd="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireUppercaseCharacters=true&";
        Pair<Integer, String> passwdPolicy=IAMTestUtils.invokeHttpsRequest(bodyPasswd, accessKey, secretKey);
        assertEquals(200, passwdPolicy.first().intValue()); 
        
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=abcde12345";
        Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, createPasswd.first().intValue());
           
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=abcde12345A";
        Pair<Integer, String> createPasswd2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, createPasswd2.first().intValue());
        AssertCreateLoginProfile(createPasswd2.second(), userName, false);
    }
	
	@Test
    public void test_createLoginProfile_SetpasswdPolicy_all() {
        IAMTestUtils.TrancateTable("iam-passwordPolicy-yx");
        String userName="subuser_test35";
        String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        assertEquals(200, resultPair.first().intValue());
        AssertCreateUserResult(resultPair.second(), userName, null);
        
        String bodyPasswd="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireUppercaseCharacters=true&RequireSymbols=true&MinimumPasswordLength=10";
        Pair<Integer, String> passwdPolicy=IAMTestUtils.invokeHttpsRequest(bodyPasswd, accessKey, secretKey);
        assertEquals(200, passwdPolicy.first().intValue()); 
        
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=abcde12345";
        Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, createPasswd.first().intValue());
        
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=abcde12345A";
        Pair<Integer, String> createPasswd2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, createPasswd2.first().intValue());
        
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=abcde1A#";
        Pair<Integer, String> createPasswd3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, createPasswd3.first().intValue());
           
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=abcde123A#";
        Pair<Integer, String> createPasswd4=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, createPasswd4.first().intValue());
        AssertCreateLoginProfile(createPasswd4.second(), userName, false);
    }
	
	@Test
	public void test_updateLoginProfile() {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		body="Action=UpdateLoginProfile&UserName="+userName+"&Password=b87654321";
		Pair<Integer, String> updatePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, updatePasswd.first().intValue());

	}
	
	
	
	@Test
	/*
	 * 没有设置密码修改密码
	 */
	public void test_updateLoginProfile_noOldPasswd() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=UpdateLoginProfile&UserName="+userName+"&Password=b87654321";
		Pair<Integer, String> updatePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, updatePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(updatePasswd.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("Login Profile for User subuser_test31 cannot be found.", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 没有username参数
	 */
	public void test_updateLoginProfile_NoUserNameParam() throws JSONException {
		String body="Action=UpdateLoginProfile&Password=b87654321";
		Pair<Integer, String> updatePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, updatePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(updatePasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * username在数据库不存在
	 */
	public void test_updateLoginProfile_NoUserName() throws JSONException {
		String userName="nouser";
		String body="Action=UpdateLoginProfile&Password=b87654321&UserName="+userName;
		Pair<Integer, String> updatePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, updatePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(updatePasswd.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name nouser cannot be found.", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	
	
	@Test
	/*
	 * 没有password参数
	 */
	public void test_updateLoginProfile_NoPasswordParam() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		body="Action=UpdateLoginProfile&UserName="+userName;
		Pair<Integer, String> updatePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, updatePasswd.first().intValue());
	}
	
	@Test
	/*
	 * password为0位
	 */
	public void test_updateLoginProfile_Password0Charater() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		body="Action=UpdateLoginProfile&UserName="+userName+"&Password=";
		Pair<Integer, String> updatePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, updatePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(updatePasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("2 validation errors detected: Value '' at 'password' failed to satisfy constraint: Member must have length greater than or equal to 8; Value at 'password' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\u0009\\u000A\\u000D\\u0020-\\u00FF]+", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * password不够8位
	 */
	public void test_updateLoginProfile_Password7Charater() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		body="Action=UpdateLoginProfile&UserName="+userName+"&Password="+UrlEncoded.encodeString("a 12345");
		Pair<Integer, String> updatePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, updatePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(updatePasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value 'a 12345' at 'password' failed to satisfy constraint: Member must have length greater than or equal to 8", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * password设置128位
	 */
	public void test_updateLoginProfile_Password128Charater() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		body="Action=UpdateLoginProfile&UserName="+userName+"&Password=a2345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678";
		Pair<Integer, String> updatePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, updatePasswd.first().intValue());
		
	}
	
	@Test
	/*
	 * password超过129位
	 */
	public void test_updateLoginProfile_Password129Charater() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		body="Action=UpdateLoginProfile&UserName="+userName+"&Password=a23456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
		Pair<Integer, String> updatePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, updatePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(updatePasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value 'a23456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789' at 'password' failed to satisfy constraint: Member must have length less than or equal to 128", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * PasswordResetRequired设置true
	 */
	public void test_updateLoginProfile_PasswordResetRequiredTrue() {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678&PasswordResetRequired=false";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		body="Action=UpdateLoginProfile&UserName="+userName+"&Password=b87654321&PasswordResetRequired=true";
		Pair<Integer, String> updatePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, updatePasswd.first().intValue());
	}
	
	@Test
	/*
	 * PasswordResetRequired设置false
	 */
	public void test_updateLoginProfile_PasswordResetRequiredfalse() {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678&PasswordResetRequired=true";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, true);
		
		body="Action=UpdateLoginProfile&UserName="+userName+"&Password=b87654321&PasswordResetRequired=false";
		Pair<Integer, String> updatePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, updatePasswd.first().intValue());
	}
	
	@Test
	/*
	 * PasswordResetRequired设置false
	 */
	public void test_updateLoginProfile_PasswordResetRequiredNotBool() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678&PasswordResetRequired=true";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, true);
		
		body="Action=UpdateLoginProfile&UserName="+userName+"&Password=b87654321&PasswordResetRequired=fa";
		Pair<Integer, String> updatePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, updatePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(updatePasswd.second());
		assertEquals("MalformedInput", error.get("Code"));
		assertEquals("Invalid Argument.", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
    public void test_updateLoginProfile_SetpasswdPolicy_all() {
        IAMTestUtils.TrancateTable("iam-passwordPolicy-yx");
        String userName="subuser_test36";
        String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        assertEquals(200, resultPair.first().intValue());
        AssertCreateUserResult(resultPair.second(), userName, null);
        
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=abcde12345";
        Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, createPasswd.first().intValue());
        
        String bodyPasswd="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireUppercaseCharacters=true&RequireSymbols=true&MinimumPasswordLength=10";
        Pair<Integer, String> passwdPolicy=IAMTestUtils.invokeHttpsRequest(bodyPasswd, accessKey, secretKey);
        assertEquals(200, passwdPolicy.first().intValue()); 
        
        body="Action=UpdateLoginProfile&UserName="+userName+"&Password=abcde12345";
        Pair<Integer, String> updatePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, updatePasswd.first().intValue());
        
        body="Action=UpdateLoginProfile&UserName="+userName+"&Password=abcde12345A";
        Pair<Integer, String> createPasswd2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, createPasswd2.first().intValue());
        
        body="Action=UpdateLoginProfile&UserName="+userName+"&Password=abcde1A#";
        Pair<Integer, String> createPasswd3=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, createPasswd3.first().intValue());
           
        body="Action=UpdateLoginProfile&UserName="+userName+"&Password=abcde123A#";
        Pair<Integer, String> createPasswd4=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, createPasswd4.first().intValue());
        AssertCreateLoginProfile(createPasswd4.second(), userName, false);
    }
	
	@Test
	public void test_deleteLoginProfile() {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		body="Action=DeleteLoginProfile&UserName="+userName;
		Pair<Integer, String> deletePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, deletePasswd.first().intValue());
	}
	
	@Test
	/*
	 * username参数不存在
	 */
	public void test_deleteLoginProfile_NoUsernameParam() throws JSONException {
		String body="Action=DeleteLoginProfile";
		Pair<Integer, String> deletePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, deletePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(deletePasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * username再数据库不存在
	 */
	public void test_deleteLoginProfile_NoUsername() throws JSONException {
		String userName="nouser";
		String body="Action=DeleteLoginProfile&UserName="+userName;
		Pair<Integer, String> deletePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, deletePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(deletePasswd.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name nouser cannot be found.", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	@Test
	/*
	 * 用户没有设置登录密码
	 */
    public void test_deleteLoginProfile_noLoginfile() throws JSONException {
        String userName="subuser_nologinfile";
        String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        
        assertEquals(200, resultPair.first().intValue());
        AssertCreateUserResult(resultPair.second(), userName, null);
        
        body="Action=DeleteLoginProfile&UserName="+userName;
        Pair<Integer, String> deletePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(404, deletePasswd.first().intValue());
        JSONObject error=IAMTestUtils.ParseErrorToJson(deletePasswd.second());
        assertEquals("NoSuchEntity", error.get("Code"));
        assertEquals("Login Profile for User "+userName+" cannot be found.", error.get("Message"));
        assertEquals(userName, error.get("Resource"));
    }
	
	@Test
	public void test_changePassword() throws IOException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		// 插入数据库aksk
		String ak="yx";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=cdef1234";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(200, changePasswd.first().intValue());
	}
	
	@Test
	/*
	 * 其他人改密码
	 */
	public void test_changePassword_otherUser() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=absc1234";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(403, changePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(changePasswd.second());
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("Only IAM Users can change their own password.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		
	}
	
	@Test
	/*
	 * 新旧密码一致
	 */
	public void test_changePassword_samePasswd() throws IOException, JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		// 插入数据库aksk
		String ak="yx";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=a12345678";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(400, changePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(changePasswd.second());
		assertEquals("PasswordPolicyViolation", error.get("Code"));
		assertEquals("Policy constraint violation with password reuse prevention during password change.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	/*
	 * 没有旧密码参数
	 */
	public void test_changePassword_NoOldPasswdParam() throws JSONException, IOException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		// 插入数据库aksk
		String ak="yx";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		body="Action=ChangePassword&UserName="+userName+"&NewPassword=a12345678";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(400, changePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(changePasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'oldPassword' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	/*
	 * 旧密码和数据库中不一致
	 */
	public void test_changePassword_NoOldPasswdError() throws JSONException, IOException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		// 插入数据库aksk
		String ak="yx";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=b12345678&NewPassword=c12345678";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(403, changePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(changePasswd.second());
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("The old password was incorrect.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	/*
	 * 没有新密码参数
	 */
	public void test_changePassword_NoNewPasswdParam() throws IOException, JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		// 插入数据库aksk
		String ak="yx";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(400, changePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(changePasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'newPassword' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	/*
	 * 新密码0位
	 */
	public void test_changePassword_NoNewPasswd0Charater() throws IOException, JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		// 插入数据库aksk
		String ak="yx";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(400, changePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(changePasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("2 validation errors detected: Value '' at 'newPassword' failed to satisfy constraint: Member must have length greater than or equal to 8; Value at 'newPassword' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\u0009\\u000A\\u000D\\u0020-\\u00FF]+", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	/*
	 * 新密码不够8位
	 */
	public void test_changePassword_NoNewPasswd7Charater() throws JSONException, IOException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		// 插入数据库aksk
		String ak="yx";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=cdef123";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(400, changePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(changePasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value 'cdef123' at 'newPassword' failed to satisfy constraint: Member must have length greater than or equal to 8", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	/*
	 * 新密码128位
	 */
	public void test_changePassword_NoNewPasswd128Charater() throws IOException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		// 插入数据库aksk
		String ak="yx";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=a2345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(200, changePasswd.first().intValue());
		
	}
	
	@Test
	/*
	 * 新密码129位
	 */
	public void test_changePassword_NoNewPasswd129Charater() throws IOException, JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		// 插入数据库aksk
		String ak="yx";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=a23456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(400, changePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(changePasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value 'a23456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789' at 'newPassword' failed to satisfy constraint: Member must have length less than or equal to 128", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	/*
	 * 新密码只有数字
	 */
	public void test_changePassword_NoNewPasswd_OnlyNum() throws JSONException, IOException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		// 插入数据库aksk
		String ak="yx";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=12345678";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(400, changePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(changePasswd.second());
		assertEquals("PasswordPolicyViolation", error.get("Code"));
		assertEquals("Password does not conform to the account password policy.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	/*
	 * 新密码只有小写
	 */
	public void test_changePassword_NoNewPasswd_OnlylowerAlp() throws JSONException, IOException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		// 插入数据库aksk
		String ak="yx";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=cdefghijk";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(400, changePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(changePasswd.second());
		assertEquals("PasswordPolicyViolation", error.get("Code"));
		assertEquals("Password does not conform to the account password policy.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	/*
	 * 同时包含大小写数字特殊字符，长度不能低于10
	 */
	public void test_changePassword_HasAccountPasswordPolicy() throws IOException, JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		// 插入数据库aksk
		String ak="yx";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		int MaxPasswordAge=0;
		int MinimumPasswordLength=10;
		int PasswordReusePrevention=3;
		boolean RequireLowercaseCharacters=true;
		boolean RequireNumbers=true;
		boolean RequireSymbols=true;
		boolean RequireUppercaseCharacters=true;
		
		
		body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&MaxPasswordAge="+MaxPasswordAge+"&MinimumPasswordLength="+MinimumPasswordLength+"&PasswordReusePrevention="+PasswordReusePrevention+"&RequireLowercaseCharacters="+RequireLowercaseCharacters+"&RequireNumbers="+RequireNumbers+"&RequireSymbols="+RequireSymbols+"&RequireUppercaseCharacters="+RequireUppercaseCharacters;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		// 够8位不够10位
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=abCD@#12";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(400, changePasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(changePasswd.second());
		assertEquals("PasswordPolicyViolation", error.get("Code"));
		assertEquals("Password does not conform to the account password policy.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		
		// 够10位但只包含小写和数字
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=a123456789";
		Pair<Integer, String> changePasswd2=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(400, changePasswd2.first().intValue());
		JSONObject error2=IAMTestUtils.ParseErrorToJson(changePasswd2.second());
		assertEquals("PasswordPolicyViolation", error2.get("Code"));
		assertEquals("Password does not conform to the account password policy.", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
		
		// 够10为包含大小写数字
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=aB234567890";
		Pair<Integer, String> changePasswd3=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(400, changePasswd3.first().intValue());
		JSONObject error3=IAMTestUtils.ParseErrorToJson(changePasswd3.second());
		assertEquals("PasswordPolicyViolation", error3.get("Code"));
		assertEquals("Password does not conform to the account password policy.", error3.get("Message"));
		assertEquals("/", error3.get("Resource"));
		
		
		// 够10为包含大小写数字特殊字符
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=aB23456789@com";
		Pair<Integer, String> changePasswd4=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(200, changePasswd4.first().intValue());
		
		body="Action=DeleteAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, delete.first().intValue());
	}
	
	@Test
	/*
	 * 密码重复默认为0
	 */
	public void test_changePassword_HasAccountPasswordPolicy_PasswordReusePrevention0() throws IOException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		// 插入数据库aksk
		String ak="yx";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		
		// 修改密码
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=abCD@#12";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(200, changePasswd.first().intValue());
		
		// 修改密码为第一次使用密码
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=abCD@#12&NewPassword=a12345678";
		Pair<Integer, String> changePasswd2=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(200, changePasswd2.first().intValue());
	}
	
	@Test
	/*
	 * 密码重复设置为2
	 */
	public void test_changePassword_HasAccountPasswordPolicy_PasswordReusePrevention2() throws IOException, JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		String userId=AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		// 插入数据库aksk
		String ak="yx";
		String sk="lalalal";
		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = userId;
		aksk.userName = userName;
		aksk.accessKey=ak;
		aksk.setSecretKey(sk);
		metaClient.akskInsert(aksk);
		User user1 = new User();
		user1.accountId = "3fdmxmc3pqvmp";
		user1.userName = userName;
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk.accessKey);       
		HBaseUtils.put(user1);
		
		// 设置密码策略PasswordReusePrevention的值为2
		int PasswordReusePrevention=2;
		body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&PasswordReusePrevention="+PasswordReusePrevention;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		// 修改密码
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=abCD@#12";
		Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(200, changePasswd.first().intValue());
		
		// 修改密码为第一次使用密码
		body="Action=ChangePassword&UserName="+userName+"&OldPassword=abCD@#12&NewPassword=a12345678";
		Pair<Integer, String> changePasswd2=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
		assertEquals(400, changePasswd2.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(changePasswd2.second());
		assertEquals("PasswordPolicyViolation", error.get("Code"));
		assertEquals("Policy constraint violation with password reuse prevention during password change.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		
		body="Action=DeleteAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, delete.first().intValue());
	}
	
	@Test
	/*
	 * 获取login profile
	 */
	public void test_getLoginProfile() {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		body="Action=GetLoginProfile&UserName="+userName;
		Pair<Integer, String> getPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, getPasswd.first().intValue());
		AssertGetLoginProfile(getPasswd.second(), userName, false);
	}
	
	@Test
	/*
	 * 获取login profile PasswordResetRequired=true
	 */
	public void test_getLoginProfile_passwordResetRequiredTrue() {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678"+"&PasswordResetRequired=true";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, true);
		
		body="Action=GetLoginProfile&UserName="+userName;
		Pair<Integer, String> getPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, getPasswd.first().intValue());
		AssertGetLoginProfile(getPasswd.second(), userName, true);
	}
	
	@Test
	/*
	 * 获取login profile PasswordResetRequired=false
	 */
	public void test_getLoginProfile_passwordResetRequiredFalse() {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678"+"&PasswordResetRequired=false";
		Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, createPasswd.first().intValue());
		AssertCreateLoginProfile(createPasswd.second(), userName, false);
		
		body="Action=GetLoginProfile&UserName="+userName;
		Pair<Integer, String> getPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, getPasswd.first().intValue());
		AssertGetLoginProfile(getPasswd.second(), userName, false);
	}
	
	@Test
	/*
	 * 获取login profile 没有username参数
	 */
	public void test_getLoginProfile_noUsernameParam() throws JSONException {
		
		String body="Action=GetLoginProfile";
		Pair<Integer, String> getPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, getPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(getPasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * 获取login profile 没有username参数为空
	 */
	public void test_getLoginProfile_username0Charater() throws JSONException {
		
		String body="Action=GetLoginProfile&UserName=";
		Pair<Integer, String> getPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, getPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(getPasswd.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: The specified value for 'userName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-", error.get("Message"));
		assertEquals("", error.get("Resource"));
	}
	
	@Test
	/*
	 * 获取login profile 没有username再数据库中不存在
	 */
	public void test_getLoginProfile_noUser() throws JSONException {
		String username="nouser";
		String body="Action=GetLoginProfile&UserName="+username;
		Pair<Integer, String> getPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, getPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(getPasswd.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The user with name " + username + " cannot be found.", error.get("Message"));
		assertEquals(username, error.get("Resource"));
	}
	
	
	@Test
	/*
	 * 获取login profile 没有设置login profile
	 */
	public void test_getLoginProfile_NoPasswd() throws JSONException {
		String userName="subuser_test31";
		String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		
		assertEquals(200, resultPair.first().intValue());
		AssertCreateUserResult(resultPair.second(), userName, null);
		
		body="Action=GetLoginProfile&UserName="+userName;
		Pair<Integer, String> getPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, getPasswd.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(getPasswd.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("Login Profile for User " + userName + " cannot be found.", error.get("Message"));
		assertEquals(userName, error.get("Resource"));
	}
	
	
	public String AssertCreateUserResult(String xml,String userName,List<Pair<String,String>> tags) {
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        Element createUserResultElement=root.getChild("CreateUserResult");
	        Element UserElement=createUserResultElement.getChild("User");
	        
	        String userId=UserElement.getChild("UserId").getValue();
	        System.out.println(userId);
	        assertEquals(userName, UserElement.getChild("UserName").getValue());
	       
	        if (tags!=null&&tags.size()>0) {
	        	@SuppressWarnings("unchecked")
				List<Element> memberElements=UserElement.getChild("Tags").getChildren("member");
	        	for (int i = 0; i < tags.size(); i++) {
	        		Pair<String, String> pair= tags.get(i);
	        		assertEquals(pair.first(), memberElements.get(i).getChild("Key").getValue());
	                assertEquals(pair.second(), memberElements.get(i).getChild("Value").getValue());
				}	
				System.out.println("verify tags");
			}
	        
	        System.out.println(UserElement.getChild("CreateDate").getValue());
	        System.out.println(UserElement.getChild("Arn").getValue());
	        
	        return userId;
		} catch (Exception e) {
			// TODO: handle exception
		}
		
		return null;
  
	}
	
	public void AssertGetUserResult(String xml,String userName,List<Pair<String,String>> tags) {
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        Element createUserResultElement=root.getChild("GetUserResult");
	        Element UserElement=createUserResultElement.getChild("User");
	        
	        System.out.println(UserElement.getChild("UserId").getValue());
	        if (userName!=null) {
	        	assertEquals(userName, UserElement.getChild("UserName").getValue());
			}
	       
	        if (tags!=null&&tags.size()>0) {
	        	@SuppressWarnings("unchecked")
				List<Element> memberElements=UserElement.getChild("Tags").getChildren("member");
	        	for (int i = 0; i < tags.size(); i++) {
	        		Pair<String, String> pair= tags.get(i);
	        		assertEquals(pair.first(), memberElements.get(i).getChild("Key").getValue());
	                assertEquals(pair.second(), memberElements.get(i).getChild("Value").getValue());
				}	
				System.out.println("verify tags");
			}
	        
	        System.out.println(UserElement.getChild("CreateDate").getValue());
	        if ("1970-01-01T00:00:00Z".equals(UserElement.getChild("CreateDate").getValue())) {
				assertTrue(false);
			}
	        System.out.println(UserElement.getChild("Arn").getValue());
	        
	        if (UserElement.getChild("PasswordLastUsed")!=null) {
	        	System.out.println(UserElement.getChild("PasswordLastUsed").getValue());
	        	if ("1970-01-01T00:00:00Z".equals(UserElement.getChild("PasswordLastUsed").getValue())) {
	        		assertTrue(false);
				}
			}
	        if (UserElement.getChild("IPLastUsed")!=null) {
	        	System.out.println(UserElement.getChild("IPLastUsed").getValue());
	        	if ("1970-01-01T00:00:00Z".equals(UserElement.getChild("IPLastUsed").getValue())) {
	        		assertTrue(false);
				}
			}
	        
		} catch (Exception e) {
			// TODO: handle exception
		}
  
	}
	
	public String AssertlistUsersResult(String xml,Map<String,Pair<Integer,Integer>> users,boolean truncate) {
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        Element listUserResultElement=root.getChild("ListUsersResult");
	        Element UsersElement=listUserResultElement.getChild("Users");
	        
	        if (users!=null&&users.size()>0) {
	        	@SuppressWarnings("unchecked")
				List<Element> membersElement=UsersElement.getChildren("member");
	        	for (Element element : membersElement) {
					String username=element.getChild("UserName").getValue();
					assertTrue(users.containsKey(username));
					System.out.println("UserName="+username);
					System.out.println("UserId="+element.getChild("UserId").getValue());
					System.out.println("CreateDate="+element.getChild("CreateDate").getValue());
					System.out.println("AccessKeyCount="+element.getChild("AccessKeyCount").getValue());
                    System.out.println("MFADeviceCount="+element.getChild("MFADeviceCount").getValue());
                    
                    int AccessKeyCount=users.get(username).first();
                    int MFADeviceCount=users.get(username).second();
                    assertEquals(String.valueOf(AccessKeyCount), element.getChild("AccessKeyCount").getValue());
                    assertEquals(String.valueOf(MFADeviceCount), element.getChild("MFADeviceCount").getValue());
                    
					if ("1970-01-01T00:00:00Z".equals(element.getChild("CreateDate").getValue())) {
						assertTrue(false);
					}
					System.out.println("Arn="+element.getChild("Arn").getValue());
					if (element.getChild("PasswordLastUsed")!=null) {
						System.out.println("PasswordLastUsed="+element.getChild("PasswordLastUsed").getValue());
					}
				}
			}
	        
	        assertEquals(String.valueOf(truncate), listUserResultElement.getChild("IsTruncated").getValue());
	        
	        if (truncate) {
				return listUserResultElement.getChild("Marker").getValue();
			}
		} catch (Exception e) {
			// TODO: handle exception
		}
		
		return null;
		
	}
	
	public String AssertListTags(String xml,List<Pair<String,String>> tags,boolean truncate) {
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        Element listTagsResultElement=root.getChild("ListUserTagsResult");
	        if (tags!=null&&tags.size()>0) {
	        	@SuppressWarnings("unchecked")
				List<Element> memberElements=listTagsResultElement.getChild("Tags").getChildren("member");
	        	for (int i = 0; i < tags.size(); i++) {
	        		Pair<String, String> pair= tags.get(i);
	        		assertEquals(pair.first(), memberElements.get(i).getChild("Key").getValue());
	                assertEquals(pair.second(), memberElements.get(i).getChild("Value").getValue());
				}	
				System.out.println("verify tags");
			}
	        
	        assertEquals(String.valueOf(truncate), listTagsResultElement.getChild("IsTruncated").getValue());
	        if (truncate) {
				return listTagsResultElement.getChild("Marker").getValue();
			}
		} catch (Exception e) {
			// TODO: handle exception
		}
		return null;
	}
	
	public String AssertlistGroupForUser(String xml,List<String> groups,boolean truncate) {
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        Element listUserResultElement=root.getChild("ListGroupsForUserResult");
	        Element UsersElement=listUserResultElement.getChild("Groups");
	        
	        if (groups!=null&&groups.size()>0) {
	        	@SuppressWarnings("unchecked")
				List<Element> membersElement=UsersElement.getChildren("member");
	        	for (Element element : membersElement) {
					String username=element.getChild("GroupName").getValue();
					assertTrue(groups.contains(username));
					System.out.println("UserId="+element.getChild("GroupId").getValue());
					System.out.println("CreateDate="+element.getChild("CreateDate").getValue());
					if ("1970-01-01T00:00:00Z".equals(element.getChild("CreateDate").getValue())) {
						assertTrue(false);
					}
					System.out.println("Arn="+element.getChild("Arn").getValue());
				}
			}
	        
	        assertEquals(String.valueOf(truncate), listUserResultElement.getChild("IsTruncated").getValue());
	        
	        if (truncate) {
				return listUserResultElement.getChild("Marker").getValue();
			}
		} catch (Exception e) {
			// TODO: handle exception
		}
		
		return null;
		
	}
	
	public void AssertCreateLoginProfile(String xml,String userName,boolean PasswordResetRequired){
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        Element CreateLoginProfileResultElement=root.getChild("CreateLoginProfileResult");
	        Element LoginProfileElement=CreateLoginProfileResultElement.getChild("LoginProfile");
	        
	       
	        assertEquals(userName, LoginProfileElement.getChild("UserName").getValue());
	        System.out.println(LoginProfileElement.getChild("CreateDate").getValue());
	        if ("1970-01-01T00:00:00Z".equals(LoginProfileElement.getChild("CreateDate").getValue())) {
				assertTrue(false);
			}
	        assertEquals(String.valueOf(PasswordResetRequired), LoginProfileElement.getChild("PasswordResetRequired").getValue());
	        
		} catch (Exception e) {
			// TODO: handle exception
		}
	}
	
	public void AssertGetLoginProfile(String xml,String userName,boolean resetRequired) {
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        Element getLoginProfileResultElement=root.getChild("GetLoginProfileResult");
	        Element LoginProfileElement=getLoginProfileResultElement.getChild("LoginProfile");
	        
	       
	        assertEquals(userName, LoginProfileElement.getChild("UserName").getValue());
	        System.out.println(LoginProfileElement.getChild("CreateDate").getValue());
	        if ("1970-01-01T00:00:00Z".equals(LoginProfileElement.getChild("CreateDate").getValue())) {
				assertTrue(false);
			}
	        assertEquals(String.valueOf(resetRequired), LoginProfileElement.getChild("PasswordResetRequired").getValue());
			
		} catch (Exception e) {
			// TODO: handle exception
		}
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
	
	public Pair<String, String> CreateIdentifyingCode(String secret) {
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
}
