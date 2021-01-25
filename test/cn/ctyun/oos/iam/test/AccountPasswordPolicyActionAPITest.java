package cn.ctyun.oos.iam.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.io.IOUtils;
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
import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class AccountPasswordPolicyActionAPITest {
	
	public static final String OOS_IAM_DOMAIN="https://oos-cd-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName="cd";
	
	private static String ownerName = "root_user1@test.com";
	public static final String accessKey="userak1";
	public static final String secretKey="usersk1";
	public static final String accountId="3fdmxmc3pqvmp";
	public static final String user1accessKey1="abcdefghijklmnop";
    public static final String user1secretKey1="cccccccccccccccc";
    public static final String user1Name="test_1";
	
	
	
	public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	    IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);
        
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
        
        metaClient.akskInsert(aksk1);
        user1.accessKeys.add(aksk1.accessKey);
        HBaseUtils.put(user1);
	}

	@Before
	public void setUp() throws Exception {
		IAMTestUtils.TrancateTable("iam-passwordPolicy-yx");
//		IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(accessKey, secretKey, 200);
	}

	@Test
	public void test_getAccountPasswordPolicy_default() throws Exception{
		String body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 0, 8, 0);
	}
	
	
	@Test
	public void test_updateAccountPasswordPolicy_AllowUsersToChangePassword_false() {
		boolean AllowUsersToChangePassword=false;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&AllowUsersToChangePassword="+AllowUsersToChangePassword;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), false, false, true, true, false, false, 0, 8, 0);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_AllowUsersToChangePassword_true(){
		boolean AllowUsersToChangePassword=true;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&AllowUsersToChangePassword="+AllowUsersToChangePassword;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 0, 8, 0);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_AllowUsersToChangePassword_NotBool() throws JSONException{

		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&AllowUsersToChangePassword=aa";
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, update.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(update.second());
		assertEquals("MalformedInput", error.get("Code"));
		assertEquals("Invalid Argument.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		
	}
	
	@Test
	public void test_updateAccountPasswordPolicy_HardExpiry_true() {
		boolean HardExpiry=true;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&HardExpiry="+HardExpiry;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, true, true, true, false, false, 0, 8, 0);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_HardExpiry_false() {
		boolean HardExpiry=false;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&HardExpiry="+HardExpiry;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 0, 8, 0);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_HardExpiry_NotBool() throws JSONException {
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&HardExpiry=bb";
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, update.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(update.second());
		assertEquals("MalformedInput", error.get("Code"));
		assertEquals("Invalid Argument.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	public void test_updateAccountPasswordPolicy_MaxPasswordAge_1() {
		int MaxPasswordAge=1;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&MaxPasswordAge="+MaxPasswordAge;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 1, 8, 0);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_MaxPasswordAge_1095() {
		int MaxPasswordAge=1095;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&MaxPasswordAge="+MaxPasswordAge;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 1095, 8, 0);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_MaxPasswordAge_1096() throws JSONException {
		int MaxPasswordAge=1096;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&MaxPasswordAge="+MaxPasswordAge;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, update.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(update.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '1096' at 'maxPasswordAge' failed to satisfy constraint: Member must have value less than or equal to 1095", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	public void test_updateAccountPasswordPolicy_MaxPasswordAge_0() {
		int MaxPasswordAge=0;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&MaxPasswordAge="+MaxPasswordAge;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 0, 8, 0);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_MinimumPasswordLength_7() throws JSONException {
		int MinimumPasswordLength=7;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&MinimumPasswordLength="+MinimumPasswordLength;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, update.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(update.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '7' at 'minimumPasswordLength' failed to satisfy constraint: Member must have value greater than or equal to 8", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	public void test_updateAccountPasswordPolicy_MinimumPasswordLength_8() {
		int MinimumPasswordLength=8;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&MinimumPasswordLength="+MinimumPasswordLength;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 0, 8, 0);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_MinimumPasswordLength_128() {
		int MinimumPasswordLength=128;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&MinimumPasswordLength="+MinimumPasswordLength;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 0, 128, 0);
	}
	
	@Test
	public void test_updateAccountPasswordPolicy_MinimumPasswordLength_129() throws JSONException {
		int MinimumPasswordLength=129;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&MinimumPasswordLength="+MinimumPasswordLength;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, update.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(update.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '129' at 'minimumPasswordLength' failed to satisfy constraint: Member must have value less than or equal to 128", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	@Test
	public void test_updateAccountPasswordPolicy_PasswordReusePrevention_1() {
		int PasswordReusePrevention=1;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&PasswordReusePrevention="+PasswordReusePrevention;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 0, 8, 1);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_PasswordReusePrevention_24() {
		int PasswordReusePrevention=24;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&PasswordReusePrevention="+PasswordReusePrevention;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 0, 8, 24);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_PasswordReusePrevention_25() throws JSONException {
		int PasswordReusePrevention=25;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&PasswordReusePrevention="+PasswordReusePrevention;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, update.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(update.second());
		assertEquals("ValidationError", error.get("Code"));
		assertEquals("1 validation error detected: Value '25' at 'passwordReusePrevention' failed to satisfy constraint: Member must have value less than or equal to 24", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_PasswordReusePrevention_0() {
		int PasswordReusePrevention=0;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&PasswordReusePrevention="+PasswordReusePrevention;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 0, 8, 0);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireLowercaseCharacters_false() {
		boolean RequireLowercaseCharacters=false;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireLowercaseCharacters="+RequireLowercaseCharacters;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, false, true, false, false, 0, 8, 0);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireLowercaseCharacters_true() {
		boolean RequireLowercaseCharacters=true;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireLowercaseCharacters="+RequireLowercaseCharacters;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 0, 8, 0);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireLowercaseCharacters_NotBool() throws JSONException {
		
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireLowercaseCharacters=cc";
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, update.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(update.second());
		assertEquals("MalformedInput", error.get("Code"));
		assertEquals("Invalid Argument.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireNumbers_false() {
		boolean RequireNumbers=false;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireNumbers="+RequireNumbers;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, false, false, false, 0, 8, 0);
	}
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireNumbers_true() {
		boolean RequireNumbers=true;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireNumbers="+RequireNumbers;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 0, 8, 0);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireNumbers_NotBool() throws JSONException {
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireNumbers=dd";
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, update.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(update.second());
		assertEquals("MalformedInput", error.get("Code"));
		assertEquals("Invalid Argument.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireSymbols_true() {
		boolean RequireSymbols=true;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireSymbols="+RequireSymbols;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, true, false, 0, 8, 0);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireSymbols_false() {
		boolean RequireSymbols=false;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireSymbols="+RequireSymbols;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 0, 8, 0);

	}
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireSymbols_NotBool() throws JSONException {
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireSymbols=ee";
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, update.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(update.second());
		assertEquals("MalformedInput", error.get("Code"));
		assertEquals("Invalid Argument.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireUppercaseCharacters_true() {
		boolean RequireUppercaseCharacters=true;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireUppercaseCharacters="+RequireUppercaseCharacters;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, true, 0, 8, 0);
	}
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireUppercaseCharacters_false() {
		boolean RequireUppercaseCharacters=false;
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireUppercaseCharacters="+RequireUppercaseCharacters;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		
		AssertAccountPasswordPolicy(resultPair.second(), true, false, true, true, false, false, 0, 8, 0);

	}
	
	
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireUppercaseCharacters_NotBool() throws JSONException {

		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&RequireUppercaseCharacters=ff";
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(400, update.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(update.second());
		assertEquals("MalformedInput", error.get("Code"));
		assertEquals("Invalid Argument.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	@Test
	public void test_updateAccountPasswordPolicy_AllowUsersToChangePassword() {
	    User user = new User();
        user.accountId = accountId;
        user.userName = user1Name;
        // 保存用户密码数据
        user.password = IAMStringUtils.passwordEncode("a12345678");
        user.oldPasswords = null;
        user.passwordCreateDate = System.currentTimeMillis();
        user.passwordResetRequired = false;
        try {
            HBaseUtils.put(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
	    // 默认能修改密码
        String userName=user1Name;
        String body="Action=ChangePassword&UserName="+userName+"&OldPassword=a12345678&NewPassword=cdef1234";
        Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePasswd.first().intValue());
	    
	    // AllowUsersToChangePassword 设置false, 用户不能修改密码
        test_updateAccountPasswordPolicy_AllowUsersToChangePassword_false();
        body="Action=ChangePassword&UserName="+userName+"&OldPassword=cdef1234&NewPassword=a12345678";
        Pair<Integer, String> changePasswd2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(403, changePasswd2.first().intValue());
	    
	    // AllowUsersToChangePassword 设置true, 用户可以修改密码
        test_updateAccountPasswordPolicy_AllowUsersToChangePassword_true();
        Pair<Integer, String> changePasswd3=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePasswd3.first().intValue());
        
    }
	
	@Test
	public void test_updateAccountPasswordPolicy_HardExpiry() {
	    test_updateAccountPasswordPolicy_PasswordReusePrevention_1();
	    
	    // 过期时间为一天
	    Calendar calendar = Calendar.getInstance();
	    calendar.add(Calendar.DATE, -2);
	    
	    User user = new User();
        user.accountId = accountId;
        user.userName = user1Name;
        // 保存用户密码数据
        user.password = IAMStringUtils.passwordEncode("a12345678");
        user.oldPasswords = null;
        user.passwordCreateDate = calendar.getTimeInMillis();
        user.passwordResetRequired = false;
        try {
            HBaseUtils.put(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // 默认过期能修改密码
        String body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=a12345678&NewPassword=cdef1234";
        Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePasswd.first().intValue());
        
        // HardExpiry 设置true, 密码过期用户不能修改密码仅体现在前端
        String bodytrue="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&HardExpiry=true";
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(bodytrue, accessKey, secretKey);
        assertEquals(200, update.first().intValue());
        
        user.password = IAMStringUtils.passwordEncode("a12345678");
        user.oldPasswords = null;
        user.passwordCreateDate = calendar.getTimeInMillis();
        user.passwordResetRequired = false;
        try {
            HBaseUtils.put(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // 这个字段用于前端页面跳转，后台实际可以修改密码
        Pair<Integer, String> changePasswd2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePasswd2.first().intValue());
        
        
        // HardExpiry 设置false, 密码过期用户可以修改密码
        String bodyfalse="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&HardExpiry=false";
        Pair<Integer, String> update2=IAMTestUtils.invokeHttpsRequest(bodyfalse, accessKey, secretKey);
        assertEquals(200, update2.first().intValue());
        
        user.password = IAMStringUtils.passwordEncode("a12345678");
        user.oldPasswords = null;
        user.passwordCreateDate = calendar.getTimeInMillis();
        user.passwordResetRequired = false;
        try {
            HBaseUtils.put(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        Pair<Integer, String> changePasswd3=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePasswd3.first().intValue());
    }
	
	@Test
	public void test_updateAccountPasswordPolicy_MaxPasswordAge() {
	    Calendar calendar = Calendar.getInstance();
	    calendar.add(Calendar.DATE, -4);
        // 默认密码不过期
	    User user = new User();
        user.accountId = accountId;
        user.userName = user1Name;
        user.password = IAMStringUtils.passwordEncode("a12345678");
        user.oldPasswords = null;
        user.passwordCreateDate = calendar.getTimeInMillis();
        user.passwordResetRequired = false;
        try {
            HBaseUtils.put(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        assertFalse(user.passwordExpired(0));
 
        // MaxPasswordAge 设置1, 密码一天过期
        test_updateAccountPasswordPolicy_MaxPasswordAge_1();
        assertTrue(user.passwordExpired(1));  
        
        // MaxPasswordAge 设置1095, 密码1095天过期
        test_updateAccountPasswordPolicy_MaxPasswordAge_1095();
        assertFalse(user.passwordExpired(1095));
        
        calendar.add(Calendar.DATE, -1096);
        user.passwordCreateDate = calendar.getTimeInMillis();
        user.passwordResetRequired = false;
        try {
            HBaseUtils.put(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
        assertTrue(user.passwordExpired(1095));  
	    // MaxPasswordAge 设置0,密码不过期
        test_updateAccountPasswordPolicy_MaxPasswordAge_0();
        assertFalse(user.passwordExpired(0));  
    }
	
	@Test
	public void test_updateAccountPasswordPolicy_MinimumPasswordLength() {
        // 密码长度最小为8
	    String body="Action=CreateLoginProfile&UserName="+user1Name+"&Password=a123456";
        Pair<Integer, String> createPasswd=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(400, createPasswd.first().intValue());
        
        body="Action=CreateLoginProfile&UserName="+user1Name+"&Password=a12345678";
        Pair<Integer, String> createPasswd1=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
        assertEquals(200, createPasswd1.first().intValue());
        
        // MinimumPasswordLength 设置10, 密码最小长度是10
        String bodyminiLegth="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&MinimumPasswordLength=10";
        Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(bodyminiLegth, accessKey, secretKey);
        assertEquals(200, update.first().intValue());
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=a12345678&NewPassword=cdef1234";
        Pair<Integer, String> changePwd=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(400, changePwd.first().intValue());
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=a12345678&NewPassword=cdef123456";
        Pair<Integer, String> changePwd2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd2.first().intValue());
        
        // MinimumPasswordLength 设置128, 密码最小长度是128
        test_updateAccountPasswordPolicy_MinimumPasswordLength_128();
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=cdef123456&NewPassword=abcd123456";
        Pair<Integer, String> changePwd3=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(400, changePwd3.first().intValue());
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=cdef123456&NewPassword=a1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567";
        Pair<Integer, String> changePwd4=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd4.first().intValue());
        
        // MinimumPasswordLength 设置8,密码最小长度是8
        test_updateAccountPasswordPolicy_MinimumPasswordLength_8();
        body="Action=ChangePassword&UserName="+user1Name+"&NewPassword=a12345678&OldPassword=a1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567";
        Pair<Integer, String> changePwd5=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd5.first().intValue());
    }
	
	@Test
	public void test_updateAccountPasswordPolicy_PasswordReusePrevention() {   
	    
	    User user = new User();
        user.accountId = accountId;
        user.userName = user1Name;
        user.password = IAMStringUtils.passwordEncode("a12345678");
        user.oldPasswords = Arrays.asList(IAMStringUtils.passwordEncode("b12345678"));
        user.passwordCreateDate = System.currentTimeMillis();
        user.passwordResetRequired = false;
        try {
            HBaseUtils.put(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
	    
        // 默认不阻止用户历史密码
        String body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=a12345678&NewPassword=b12345678";
        Pair<Integer, String> changePwd=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd.first().intValue());
        
        // PasswordReusePrevention 设置1, 1次之内的历史密码不允许修改
        user.oldPasswords = Arrays.asList(IAMStringUtils.passwordEncode("a12345678"),IAMStringUtils.passwordEncode("b12345678"),IAMStringUtils.passwordEncode("c12345678"));
        try {
            HBaseUtils.put(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        test_updateAccountPasswordPolicy_PasswordReusePrevention_1();
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=a12345678&NewPassword=c12345678";
        Pair<Integer, String> changePwd2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(400, changePwd2.first().intValue());
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=a12345678&NewPassword=b12345678";
        Pair<Integer, String> changePwd3=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd3.first().intValue());
        
        // PasswordReusePrevention 设置24, 24次之内的历史密码不允许修改
        List<String> oldList = new ArrayList<String>();
        for (int i = 0; i < 26; i++) {
            oldList.add(IAMStringUtils.passwordEncode((char)(97+i)+"12345678"));
        } 
        user.oldPasswords = oldList;
        try {
            HBaseUtils.put(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
        test_updateAccountPasswordPolicy_PasswordReusePrevention_24();
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=a12345678&NewPassword=c12345678";
        Pair<Integer, String> changePwd4=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(400, changePwd4.first().intValue());
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=a12345678&NewPassword=b12345678";
        Pair<Integer, String> changePwd5=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd5.first().intValue());
        
        // PasswordReusePrevention 设置0,不阻止用户历史密码
        test_updateAccountPasswordPolicy_PasswordReusePrevention_0();
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=b12345678&NewPassword=h12345678";
        Pair<Integer, String> changePwd6=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd6.first().intValue());
    }
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireLowercaseCharacters() {
	    User user = new User();
        user.accountId = accountId;
        user.userName = user1Name;
        user.password = IAMStringUtils.passwordEncode("12345678");
        user.oldPasswords = null;
        user.passwordCreateDate = System.currentTimeMillis();
        user.passwordResetRequired = false;
        try {
            HBaseUtils.put(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
	    
        // 默认必须包含小写字母
        String body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=12345678&NewPassword=23456789";
        Pair<Integer, String> changePwd=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(400, changePwd.first().intValue());
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=12345678&NewPassword=a3456789";
        Pair<Integer, String> changePwd2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd2.first().intValue());
              
        // RequireLowercaseCharacters 设置false, 不必须包含小写字母
        test_updateAccountPasswordPolicy_RequireLowercaseCharacters_false();
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=a3456789&NewPassword=23456789";
        Pair<Integer, String> changePwd3=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd3.first().intValue());
        
        // RequireLowercaseCharacters 设置true, 必须包含小写字母
        test_updateAccountPasswordPolicy_RequireLowercaseCharacters_true();
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=23456789&NewPassword=12345678";
        Pair<Integer, String> changePwd4=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(400, changePwd4.first().intValue());
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=23456789&NewPassword=a3456789";
        Pair<Integer, String> changePwd5=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd5.first().intValue());
        
    }
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireNumbers() {
	    User user = new User();
        user.accountId = accountId;
        user.userName = user1Name;
        user.password = IAMStringUtils.passwordEncode("12345678");
        user.oldPasswords = null;
        user.passwordCreateDate = System.currentTimeMillis();
        user.passwordResetRequired = false;
        try {
            HBaseUtils.put(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
	    
        // 默认必须包含数字
        String body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=12345678&NewPassword=abcdefgh";
        Pair<Integer, String> changePwd=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(400, changePwd.first().intValue());
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=12345678&NewPassword=1bcdefgh";
        Pair<Integer, String> changePwd2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd2.first().intValue());
        
        // RequireNumbers 设置false, 不必须包含数字
        test_updateAccountPasswordPolicy_RequireNumbers_false();
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=1bcdefgh&NewPassword=abcdefgh";
        Pair<Integer, String> changePwd3=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd3.first().intValue());
        
        // RequireNumbers 设置true, 必须包含数字
        test_updateAccountPasswordPolicy_RequireNumbers_true();
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=abcdefgh&NewPassword=abcdefghi";
        Pair<Integer, String> changePwd4=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(400, changePwd4.first().intValue());
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=abcdefgh&NewPassword=1bcdefgh";
        Pair<Integer, String> changePwd5=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd5.first().intValue());
        
    }
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireSymbols() {
 
	    User user = new User();
        user.accountId = accountId;
        user.userName = user1Name;
        user.password = IAMStringUtils.passwordEncode("12345678");
        user.oldPasswords = null;
        user.passwordCreateDate = System.currentTimeMillis();
        user.passwordResetRequired = false;
        try {
            HBaseUtils.put(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // 默认不必须包含特殊字符(! @ # $ % ^ & * ( ) _ + - = [ ] { } | )
        String body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=12345678&NewPassword=a2345678";
        Pair<Integer, String> changePwd=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd.first().intValue());
        
        // RequireSymbols 设置true, 必须包含特殊字符
        test_updateAccountPasswordPolicy_RequireSymbols_true();
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=a2345678&NewPassword=abcdefgh123";
        Pair<Integer, String> changePwd2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(400, changePwd2.first().intValue());
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=a2345678&NewPassword=abcdefgh123@";
        Pair<Integer, String> changePwd3=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd3.first().intValue());
        
        // RequireSymbols 设置false, 不必须包含特殊字符
        test_updateAccountPasswordPolicy_RequireSymbols_false();
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=abcdefgh123@&NewPassword=1bcdefgh";
        Pair<Integer, String> changePwd5=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd5.first().intValue());
        
    }
	
	@Test
	public void test_updateAccountPasswordPolicy_RequireUppercaseCharacters() {

	    User user = new User();
        user.accountId = accountId;
        user.userName = user1Name;
        user.password = IAMStringUtils.passwordEncode("12345678");
        user.oldPasswords = null;
        user.passwordCreateDate = System.currentTimeMillis();
        user.passwordResetRequired = false;
        try {
            HBaseUtils.put(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // 默认不必须包含大写字母
        String body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=12345678&NewPassword=a2345678";
        Pair<Integer, String> changePwd=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd.first().intValue());
        
        // RequireUppercaseCharacters 设置true, 必须包含大写字母
        test_updateAccountPasswordPolicy_RequireUppercaseCharacters_true();
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=a2345678&NewPassword=abcdefgh123";
        Pair<Integer, String> changePwd2=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(400, changePwd2.first().intValue());
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=a2345678&NewPassword=abcdefgh123D";
        Pair<Integer, String> changePwd3=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd3.first().intValue());
        
        // RequireUppercaseCharacters 设置false, 不必须包含大写字母
        test_updateAccountPasswordPolicy_RequireUppercaseCharacters_false();
        
        body="Action=ChangePassword&UserName="+user1Name+"&OldPassword=abcdefgh123D&NewPassword=1bcdefgh";
        Pair<Integer, String> changePwd4=IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
        assertEquals(200, changePwd4.first().intValue());
        
    }
	
	@Test
	public void test_deleteAccountPasswordPolicy() {
		boolean AllowUsersToChangePassword=false;
		boolean HardExpiry=true;
		int MaxPasswordAge=1000;
		int MinimumPasswordLength=12;
		int PasswordReusePrevention=3;
		boolean RequireLowercaseCharacters=false;
		boolean RequireNumbers=false;
		boolean RequireSymbols=true;
		boolean RequireUppercaseCharacters=true;
		
		
		String body="Action=UpdateAccountPasswordPolicy&Version=2010-05-08&AllowUsersToChangePassword="+AllowUsersToChangePassword+"&HardExpiry="+HardExpiry+"&MaxPasswordAge="+MaxPasswordAge+"&MinimumPasswordLength="+MinimumPasswordLength+"&PasswordReusePrevention="+PasswordReusePrevention+"&RequireLowercaseCharacters="+RequireLowercaseCharacters+"&RequireNumbers="+RequireNumbers+"&RequireSymbols="+RequireSymbols+"&RequireUppercaseCharacters="+RequireUppercaseCharacters;
		Pair<Integer, String> update=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, update.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		AssertAccountPasswordPolicy(resultPair.second(), false, true, false, false, true, true, 1000, 12, 3);

		body="Action=DeleteAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, delete.first().intValue());
		
		body="Action=GetAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> resultPair2=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair2.first().intValue());
		AssertAccountPasswordPolicy(resultPair2.second(), true, false, true, true, false, false, 0, 8, 0);

	}
	
	@Test
	public void test_deleteAccountPasswordPolicy_noPolicy() throws JSONException {
		String body="Action=DeleteAccountPasswordPolicy&Version=2010-05-08";
		Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(404, delete.first().intValue());
		JSONObject error=IAMTestUtils.ParseErrorToJson(delete.second());
		assertEquals("NoSuchEntity", error.get("Code"));
		assertEquals("The Password Policy with domain name 3fdmxmc3pqvmp cannot be found.", error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}
	
	public void AssertAccountPasswordPolicy(String xml,boolean AllowUsersToChangePassword,boolean HardExpiry, boolean RequireLowercaseCharacters,boolean RequireNumbers,boolean RequireSymbols,boolean RequireUppercaseCharacters,int MaxPasswordAge, int MinimumPasswordLength,int PasswordReusePrevention) {
		try {
			StringReader sr = new StringReader(xml);
	        InputSource is = new InputSource(sr);
	        Document doc = (new SAXBuilder()).build(is);
	        Element root = doc.getRootElement();
	        
	        Element AccountPasswordPolicyResultElement=root.getChild("GetAccountPasswordPolicyResult");
	        Element passwordPolicyElement=AccountPasswordPolicyResultElement.getChild("PasswordPolicy");
	        
	        String actualExpirePasswords=passwordPolicyElement.getChild("ExpirePasswords").getValue();
	        String actualAllowUsersToChangePassword =passwordPolicyElement.getChild("AllowUsersToChangePassword").getValue();
	        String actualHardExpiry=passwordPolicyElement.getChild("HardExpiry").getValue();
	        String actualMaxPasswordAge =passwordPolicyElement.getChild("MaxPasswordAge").getValue();
	        String actualMinimumPasswordLength=passwordPolicyElement.getChild("MinimumPasswordLength").getValue();
	        String actualPasswordReusePrevention =passwordPolicyElement.getChild("PasswordReusePrevention").getValue();
	        String actualRequireLowercaseCharacters=passwordPolicyElement.getChild("RequireLowercaseCharacters").getValue();
	        String actualRequireNumbers =passwordPolicyElement.getChild("RequireNumbers").getValue();
	        String actualRequireSymbols =passwordPolicyElement.getChild("RequireSymbols").getValue();
	        String actualRequireUppercaseCharacters =passwordPolicyElement.getChild("RequireUppercaseCharacters").getValue();
	        
	        if (MaxPasswordAge==0) {
				assertEquals("false", actualExpirePasswords);
			}else {
				assertEquals("true", actualExpirePasswords);
			}
	        
	        assertEquals(String.valueOf(AllowUsersToChangePassword), actualAllowUsersToChangePassword);
	        assertEquals(String.valueOf(HardExpiry), actualHardExpiry);
	        assertEquals(String.valueOf(RequireLowercaseCharacters), actualRequireLowercaseCharacters);
	        assertEquals(String.valueOf(RequireNumbers), actualRequireNumbers);
	        assertEquals(String.valueOf(RequireSymbols), actualRequireSymbols);
	        assertEquals(String.valueOf(RequireUppercaseCharacters), actualRequireUppercaseCharacters);
	        
	        assertEquals(String.valueOf(MaxPasswordAge), actualMaxPasswordAge);
	        assertEquals(String.valueOf(MinimumPasswordLength), actualMinimumPasswordLength);
	        assertEquals(String.valueOf(PasswordReusePrevention), actualPasswordReusePrevention);
	        
		} catch (Exception e) {
			// TODO: handle exception
		}
		
	}

}
