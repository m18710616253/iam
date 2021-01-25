package cn.ctyun.oos.iam.test.iamaccesscontrol;

import static org.junit.Assert.*;

import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
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
import cn.ctyun.oos.iam.accesscontroller.policy.Statement;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class MFAActionAccessTest {

    public static final String OOS_IAM_DOMAIN = "https://oos-cd-iam.ctyunapi.cn:9460/";
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    public static final String regionName = "cd";

    private static String ownerName = "root_user@test.com";
    public static final String accessKey = "userak";
    public static final String secretKey = "usersk";

    public static final String user1Name = "test_1";
    public static final String user2Name = "test_2";
    public static final String user3Name = "abc1";
    public static final String user1accessKey1 = "abcdefghijklmnop";
    public static final String user1secretKey1 = "cccccccccccccccc";
    public static final String user1accessKey2 = "1234567890123456";
    public static final String user1secretKey2 = "user1secretKey2lllll";
    public static final String user2accessKey = "qrstuvwxyz0000000";
    public static final String user2secretKey = "bbbbbbbbbbbbbbbbbb";
    public static final String user3accessKey = "abcdefgh12345678";
    public static final String user3secretKey = "3333333333333333";

    public static String accountId = "3rmoqzn03g6ga";
    public static String mygroupName = "mygroup";

    public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();

//  @BeforeClass
    public static void setUpBeforeClass() throws Exception {

        IAMTestUtils.TrancateTable("oos-aksk-wsy");
        IAMTestUtils.TrancateTable("iam-policy-wsy");
        IAMTestUtils.TrancateTable("iam-user-wsy");
        IAMTestUtils.TrancateTable("oos-accountSummary-wsy");
        IAMTestUtils.TrancateTable("iam-mfaDevice");
        IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);

        // 创建根用户
        owner.email = ownerName;
        owner.setPwd("123456");
        owner.maxAKNum = 10;
        owner.displayName = "测试根用户";
        owner.bucketCeilingNum = 10;
        metaClient.ownerInsertForTest(owner);

        AkSkMeta aksk = new AkSkMeta(owner.getId());
        aksk.accessKey = accessKey;
        aksk.setSecretKey(secretKey);
        aksk.isPrimary = 1;
        metaClient.akskInsert(aksk);

        String UserName1 = user1Name;
        Pair<String, String> tag = new Pair<String, String>();
        tag.first("email");
        tag.second("test1@oos.com");

        List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
        tags.add(tag);

        String body = "Action=CreateUser&Version=2010-05-08&UserName=" + UserName1 + "&Tags.member.1.Key=" + tag.first()
                + "&Tags.member.1.Value=" + tag.second();
        Pair<Integer, String> resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);

        assertEquals(200, resultPair.first().intValue());
        String userId1 = AssertCreateUserResult(resultPair.second(), UserName1, tags);

        // 插入数据库aksk
        AkSkMeta aksk1 = new AkSkMeta(owner.getId());
        aksk1.isRoot = 0;
        aksk1.userId = userId1;
        aksk1.userName = UserName1;
        aksk1.accessKey = user1accessKey1;
        aksk1.setSecretKey(user1secretKey1);
        metaClient.akskInsert(aksk1);
        User user1 = new User();
        user1.accountId = accountId;
        user1.userName = UserName1;
        user1.accessKeys = new ArrayList<>();
        user1.accessKeys.add(aksk1.accessKey);

        aksk1.accessKey = user1accessKey2;
        aksk1.setSecretKey(user1secretKey2);
        metaClient.akskInsert(aksk1);
        user1.accessKeys.add(aksk1.accessKey);
        HBaseUtils.put(user1);

        String UserName2 = user2Name;
        body = "Action=CreateUser&Version=2010-05-08&UserName=" + UserName2;
        Pair<Integer, String> resultPair2 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);

        assertEquals(200, resultPair2.first().intValue());
        String userId2 = AssertCreateUserResult(resultPair2.second(), UserName2, null);

        AkSkMeta aksk2 = new AkSkMeta(owner.getId());
        aksk2.isRoot = 0;
        aksk2.userId = userId2;
        aksk2.userName = UserName2;
        aksk2.accessKey = user2accessKey;
        aksk2.setSecretKey(user2secretKey);
        metaClient.akskInsert(aksk2);
        User user2 = new User();
        user2.accountId = accountId;
        user2.userName = UserName1;
        user2.accessKeys = new ArrayList<>();
        user2.userName = UserName2;
        user2.accessKeys.add(aksk2.accessKey);
        HBaseUtils.put(user2);

        String UserName3 = user3Name;
        body = "Action=CreateUser&Version=2010-05-08&UserName=" + UserName3;
        Pair<Integer, String> resultPair3 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);

        assertEquals(200, resultPair3.first().intValue());
        String userId3 = AssertCreateUserResult(resultPair3.second(), UserName3, null);

        AkSkMeta aksk3 = new AkSkMeta(owner.getId());
        aksk3.isRoot = 0;
        aksk3.userId = userId3;
        aksk3.userName = UserName3;
        aksk3.accessKey = user3accessKey;
        aksk3.setSecretKey(user3secretKey);
        metaClient.akskInsert(aksk3);

        User user3 = new User();
        user3.accountId = accountId;
        user3.userName = UserName1;
        user3.accessKeys = new ArrayList<>();
        user3.userName = UserName3;
        user3.accessKeys.add(aksk3.accessKey);
        HBaseUtils.put(user3);
    }

//  @Before
    public void setUp() throws Exception {
        IAMTestUtils.TrancateTable("iam-policy-wsy");
        IAMTestUtils.TrancateTable("iam-group-wsy");
        IAMTestUtils.TrancateTable("iam-mfaDevice-wsy");
//      IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
//      IAMTestUtils.TrancateTable(IAMTestUtils.iamGroupTable);
//      IAMTestUtils.TrancateTable(IAMTestUtils.iammfaDeviceTable);

        String groupName = mygroupName;
        IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name, 200);
        IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user3Name, 200);
    }

	// ========================CreateVirtualMFADevice==============================================
	/**
	 * 没有关联任何策略时，隐式拒绝。
	 * @throws JSONException
	 */
	@Test
	public void test_CreateVirtualMFADevice_noPolicy() throws JSONException {
		String MFADeviceName2 = "testVirtualMFADevice02";
		String user1bxmlString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName2, 403);
		System.out.println(user1bxmlString);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/testVirtualMFADevice02.",
				error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
	}
	
	@Test
	/*
	 * 1.allow Action=CreateVirtualMFADevice, resource=mfa/mfaDevice1
	 * 只允许创建mfaDevice1
	 */
	public void test_CreateVirtualMFADevice_Allow_Action_mfaDevice1() throws JSONException {
		// 创建policy
		String policyName = "CreateVirtualMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testVirtualMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String MFADeviceName = "testVirtualMFADevice01";
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);

		String user2xmlString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user2accessKey, user2secretKey,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/testVirtualMFADevice01.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String MFADeviceName2 = "testVirtualMFADevice02";
		String user1bxmlString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/testVirtualMFADevice02.",
				error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
	}

	@Test
	/*
	 * 2.allow Action=CreateVirtualMFADevice, resource=mfa/* 可以创建所有mfaDevice
	 */
	public void test_CreateVirtualMFADevice_Allow_Action_all() throws JSONException {
		// 创建policy
		String policyName = "CreateVirtualMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String MFADeviceName = "testVirtualMFADevice01";
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);

		String user2xmlString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user2accessKey, user2secretKey,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/testVirtualMFADevice01.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String MFADeviceName2 = "testVirtualMFADevice02";
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 3.allow Action=CreateVirtualMFADevice, resource=* 可以创建所有mfaDevice
	 */
	public void test_CreateVirtualMFADevice_Allow_Action_all2() throws JSONException {
		// 创建policy
		String policyName = "CreateVirtualMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String MFADeviceName = "testVirtualMFADevice01";
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);

		String user2xmlString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user2accessKey, user2secretKey,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/testVirtualMFADevice01.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String MFADeviceName2 = "testVirtualMFADevice02";
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);
	}

	@Test
	/*
	 * a.allow Action=CreateVirtualMFADevice, resource=user/*
	 * 资源和请求的action不匹配，policy不生效
	 */
	public void test_CreateVirtualMFADevice_Allow_Action_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyName = "CreateVirtualMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		// 验证请求
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=testVirtualMFADevice01";
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, user1.first().intValue());
		JSONObject error0 = IAMTestUtils.ParseErrorToJson(user1.second());
		assertEquals("AccessDenied", error0.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/testVirtualMFADevice01.",
				error0.get("Message"));
		assertEquals("/", error0.get("Resource"));

		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=testVirtualMFADevice01";
		Pair<Integer, String> user2 = IAMTestUtils.invokeHttpsRequest(body, user2accessKey, user2secretKey);
		assertEquals(403, user2.first().intValue());
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2.second());
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/testVirtualMFADevice01.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));

		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=testVirtualMFADevice02";
		Pair<Integer, String> user1b = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, user1b.first().intValue());
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1b.second());
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/testVirtualMFADevice02.",
				error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
	}

	@Test
	/*
	 * 4.allow NotAction=CreateVirtualMFADevice, resource=mfa/mfaDevice1
	 * 资源resource只能匹配除了CreateVirtualMFADevice的其他MFADevice相关操作
	 */
	public void test_CreateVirtualMFADevice_Allow_NotAction_mfaDevice1() throws JSONException {
		// 创建策略
		String policyName = "CreateVirtualMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给用户添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// user1创建MFADevice1 MFADevice2 都不允许
		String createMFADevice1String = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(createMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String createMFADevice2String = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(createMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		// 验证 除了 CreateVirtualMFADevice其他跟mfa/mfaDevice1相关的方法都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("CreateVirtualMFADevice");
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName);
		// 和资源不匹配的mfaDevice2不允许
		IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey1, user1secretKey1, accountId,
				MFADeviceName2);

		// listVirtualMFADevices, resource not match
		body = "Action=ListVirtualMFADevices&Version=2010-05-08";
		Pair<Integer, String> MFADeviceslist = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, MFADeviceslist.first().intValue());
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(MFADeviceslist.second());
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error3.get("Message"));
		assertEquals("/", error3.get("Resource"));
		// user1 ListMFADevices, resource not match
		body = "Action=ListMFADevices&Version=2010-05-08&UserName=" + userName;
		Pair<Integer, String> MFADeviceslist2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, MFADeviceslist2.first().intValue());
		JSONObject error4 = IAMTestUtils.ParseErrorToJson(MFADeviceslist2.second());
		assertEquals("AccessDenied", error4.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error4.get("Message"));
		assertEquals("/", error4.get("Resource"));

		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyName, policyString, accountId);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"lala_1", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 5.allow NotAction=CreateVirtualMFADevice, resource=mfa/*
	 * 资源resource只能匹配除了CreateVirtualMFADevice的其他VirtualMFADevice相关操作
	 */
	public void test_CreateVirtualMFADevice_Allow_NotAction_mfaDeviceall() throws JSONException {
		//
		String policyName = "CreateVirtualMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证user1创建VirtualMFADevice1 VirtualMFADevice2都不允许
		String createMFADevice1String = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(createMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String createMFADevice2String = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(createMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		// 验证 除了 CreateVirtualMFADevice其他跟mfa/*相关的方法都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("CreateVirtualMFADevice");
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, accountId, MFADeviceName);

		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyName, policyString, accountId);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"test_11", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 6.allow NotAction=CreateVirtualMFADevice, resource=*
	 * 可匹配除了CreateVirtualMFADevice的所有其他操作
	 */
	public void test_CreateVirtualMFADevice_Allow_NotAction_all() throws JSONException {
		// 创建策略
		String userName = "test_1";
		String policyName = "CreateVirtualMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给用户添加policy
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证user1创建VirtualMFADevice1 VirtualMFADevice2都不允许
		String createMFADevice1String = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(createMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String createMFADevice2String = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(createMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		// 验证 除了 CreateVirtualMFADevice所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("CreateVirtualMFADevice");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "CreateVirtualMFADevicePolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "group1", "mfa2");
	}

	@Test
	/*
	 * 7.allow Action=CreateVirtualMFADevice, NotResource=mfaDevice/mfaDevice1
	 * 允许CreateVirtualMFADevice 但是资源是非mfaDevice/mfaDevice1
	 */
	public void test_CreateVirtualMFADevice_Allow_Action_NotmfaDevice1() throws JSONException {
		// 创建policy
		String policyName = "CreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		String createMFADeviceString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(createMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);
	}

	@Test
	/*
	 * 8.allow Action=CreateVirtualMFADevice, NotResource=mfa/*
	 * 允许CreateVirtualMFADevice 但是资源是非mfa/*
	 */
	public void test_CreateVirtualMFADevice_Allow_Action_NotmfaDeviceALL() throws JSONException {
		// 创建policy
		String policyName = "CreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		String createMFADeviceString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(createMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String createMFADeviceString2 = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(createMFADeviceString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
	}

	@Test
	/*
	 * 9.allow Action=CreateVirtualMFADevice, NotResource:* 允许CreateVirtualMFADevice
	 * 但是资源是非*
	 */
	public void test_CreateVirtualMFADevice_Allow_Action_NotALL() throws JSONException {
		// 创建policy
		String policyName = "CreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		String createMFADeviceString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(createMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String createMFADeviceString2 = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(createMFADeviceString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
	}

	@Test
	/*
	 * 10.allow NotAction=CreateVirtualMFADevice, NotResource=mfaDevice/mfaDevice1
	 * 允许非CreateVirtualMFADevice 但是资源是非mfaDevice/mfaDevice1
	 */
	public void test_CreateVirtualMFADevice_Allow_NotAction_NotmfaDevice1() throws JSONException {
		// 创建policy
		String policyName = "CreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证创建mfaDevice1 和mfaDevice2都不允许
		String createMFADevice1String = IAMInterfaceTestUtils.CreateVirtualMFADevice(user2accessKey, user2secretKey,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(createMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String createMFADevice2String = IAMInterfaceTestUtils.CreateVirtualMFADevice(user2accessKey, user2secretKey,
				MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(createMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		// 资源为mfaDevice/mfaDevice的是都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user2accessKey, user2secretKey, accountId,
				MFADeviceName);
		// listVirtualMFADevices,允许
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 200);
		// user1 ListMFADevices, 允许
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, userName, 200);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				policyName1, policyString1, accountId);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey, null);

	}

	@Test
	/*
	 * 11.allow NotAction=CreateVirtualMFADevice, NotResource=mfa/*
	 * 允许非CreateVirtualMFADevice 但是资源是非mfa/*
	 */
	public void test_CreateVirtualMFADevice_Allow_NotAction_NotmfaALL() throws JSONException {
		// 创建policy
		String policyName = "CreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证创建group1 和group2都不允许
		String createMFADevice1String = IAMInterfaceTestUtils.CreateVirtualMFADevice(user2accessKey, user2secretKey,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(createMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String createMFADevice2String = IAMInterfaceTestUtils.CreateVirtualMFADevice(user2accessKey, user2secretKey,
				MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(createMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		// 验证资源是mfa/*的都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user2accessKey, user2secretKey, accountId,
				MFADeviceName);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				policyName1, policyString1, accountId);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey, null);
	}

	@Test
	/*
	 * 12.allow NotAction=CreateVirtualMFADevice, NotResource=*
	 * 允许非CreateVirtualMFADevice 但是资源是非*
	 */
	public void test_CreateVirtualMFADevice_Allow_NotAction_NotALL() throws JSONException {
		// 创建policy
		String policyName = "CreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证创建group1 和group2都不允许
		String createMFADevice1String = IAMInterfaceTestUtils.CreateVirtualMFADevice(user2accessKey, user2secretKey,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(createMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String createMFADevice2String = IAMInterfaceTestUtils.CreateVirtualMFADevice(user2accessKey, user2secretKey,
				MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(createMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:CreateVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21",
				tags, policyName, policyString, accountId, "group1", "mfa3");
	}

	@Test
	/*
	 * 13.Deny Action=CreateVirtualMFADevice, resource=mfa/mfaDevice1
	 * 显示拒绝创建mfaDevice1
	 */
	public void test_CreateVirtualMFADevice_Deny_Action_mfaDevice1() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyCreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);

		String policyName2 = "AllowCreateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建mfaDevice，但有权限delete(没有get,list资源不匹配)
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

	}

	@Test
	/*
	 * 14.Deny Action=CreateVirtualMFADevice, resource=mfa/*
	 */
	public void test_CreateVirtualMFADevice_Deny_Action_mfaall() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyCreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);

		String policyName2 = "AllowCreateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建mfaDevice，但有权限delete和list
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);

		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);
	}

	@Test
	/*
	 * 15.Deny Action=CreateVirtualMFADevice, resource=*
	 */
	public void test_CreateVirtualMFADevice_Deny_Action_all() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyCreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);

		String policyName2 = "AllowCreateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(
				Effect.Allow, null, null, "Action", Arrays.asList("iam:CreateVirtualMFADevice",
						"iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建mfaDevice，但有权限delete和list
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);
	}

	@Test
	/*
	 * b.Deny Action=CreateVirtualMFADevice, resource=user/* 资源不匹配，deny失败
	 */
	public void test_CreateVirtualMFADevice_Deny_Action_ReourceNotMatch() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyCreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝资源不匹配未生效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);

		String policyName2 = "AllowCreateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝未生效，有显示允许，user1可以create，delete和list
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);
	}

	@Test
	/*
	 * 16.Deny Action=CreateVirtualMFADevice, NotResource=mfa/mfaDevice1
	 * 资源非mfaDevice1,显示拒绝mfaDevice1失效，显示拒绝mfaDevice2生效
	 */
	public void test_CreateVirtualMFADevice_Deny_Action_NotResouce_mfa1() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyCreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 403);

		String policyName2 = "AllowCreateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝mfaDevice1失效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// 显示拒绝mfaDevice2生效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 403);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 17.Deny Action=CreateVirtualMFADevice, NotResource=mfa/*
	 */
	public void test_CreateVirtualMFADevice_Deny_Action_NotResouce_mfaAll() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyCreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 403);

		String policyName2 = "AllowCreateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝mfaDevice1失效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// 显示拒绝mfaDevice2失效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 18.Deny Action=CreateVirtualMFADevice, NotResource=*
	 */
	public void test_CreateVirtualMFADevice_Deny_Action_NotResouce_All() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyCreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 403);

		String policyName2 = "AllowCreateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝mfaDevice1失效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// 显示拒绝mfaDevice2失效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 19.Deny NotAction=CreateVirtualMFADevice, Resource=mfa/mfaDevice1
	 */
	public void test_CreateVirtualMFADevice_Deny_NotAction_Resource_mfa1() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyCreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 403);

		String policyName2 = "AllowCreateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝除创建以外的方法，Enable和Deactivate因为资源匹配不上而不允许
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(user1.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

		// 显示拒绝mfaDevice2失效
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> user1b = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1b.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(user1b.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				403);

	}

	@Test
	/*
	 * 20.Deny NotAction=CreateVirtualMFADevice, Resource=mfa/*
	 */
	public void test_CreateVirtualMFADevice_Deny_NotAction_Resource_mfaAll() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyCreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 403);

		String policyName2 = "AllowCreateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝除创建以外的方法
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(user1.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);

		// 显示拒绝除创建以外的方法
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> user1b = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1b.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(user1b.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				200);
	}

	@Test
	/*
	 * 21.Deny NotAction=CreateVirtualMFADevice, Resource=*
	 */
	public void test_CreateVirtualMFADevice_Deny_NotAction_Resource_All() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyCreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 403);

		String policyName2 = "AllowCreateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝除创建以外的方法
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(user1.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);

		// 显示拒绝除创建以外的方法
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> user1b = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1b.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(user1b.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode21, authenticationCode22, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);

	}

	@Test
	/*
	 * 22.Deny NotAction=CreateVirtualMFADevice, NotResource=mfa/mfaDevice1
	 */
	public void test_CreateVirtualMFADevice_Deny_NotAction_NotResource_mfa1() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyCreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 403);

		String policyName2 = "AllowCreateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// mfaDevice1的操作都允许
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(user1.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);

		// mfaDevice2除create以外都拒绝,资源匹配不上的会允许
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> user1b = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1b.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(user1b.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 403);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				403);

	}

	@Test
	/*
	 * 23.Deny NotAction=CreateVirtualMFADevice, NotResource=mfa/*
	 */
	public void test_CreateVirtualMFADevice_Deny_NotAction_NotResource_mfaAll() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyCreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 403);

		String policyName2 = "AllowCreateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// mfaDevice1的操作除了create以外都拒绝
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(user1.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);

		// mfaDevice2的操作除了create以外都拒绝
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> user1b = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1b.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(user1b.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 403);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				403);
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 24.Deny NotAction=CreateVirtualMFADevice, NotResource=*
	 */
	public void test_CreateVirtualMFADevice_Deny_NotAction_NotResource_All() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyCreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 403);

		String policyName2 = "AllowCreateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// mfaDevice1的操作除了create以外都拒绝
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(user1.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// mfaDevice2的操作除了create以外都拒绝
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> user1b = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1b.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(user1b.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);
	}

	@Test
	/*
	 * c.在IP范围的允许访问
	 */
	public void test_CreateVirtualMFADevice_Condition_sourceIP() {
		String userName = user1Name;
		String policyName = "allowspecialIP";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.168.1.1/24")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 在IP范围
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		List<Pair<String, String>> params = new ArrayList<Pair<String, String>>();
		Pair<String, String> param1 = new Pair<String, String>();
		param1.first("X-Forwarded-For");
		param1.second("192.168.1.101");
		params.add(param1);

		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1, params);
		assertEquals(200, result.first().intValue());

		// 不在IP范围
		List<Pair<String, String>> params2 = new ArrayList<Pair<String, String>>();
		Pair<String, String> param2 = new Pair<String, String>();
		param2.first("X-Forwarded-For");
		param2.second("192.168.2.101");
		params2.add(param2);

		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,
				params2);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * d.符合username匹配允许访问
	 */
	public void test_CreateVirtualMFADevice_Condition_username() {
		String userName = "test_1";
		String policyName = "allowUsername";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// username 符合条件
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		// username 不符合条件
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(body, user3accessKey, user3secretKey);
		assertEquals(403, result3.first().intValue());
	}

	@Test
	/*
	 * e.符合实际条件允许访问
	 */
	public void test_CreateVirtualMFADevice_Condition_CurrentTime() {
		String userName = "test_1";
		String policyName = "allowDateGreate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2019-01-01T00:00:00Z")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 时间符合条件
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2050-01-01T00:00:00Z")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 时间不符合条件
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * f.设置不允许ssl访问
	 */
	public void test_CreateVirtualMFADevice_Condition_SecureTransport() {
		String userName = "test_1";
		String policyName = "DenySSL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 允许ssl访问
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("false")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 不允许ssl访问
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());

	}

	@Test
	/*
	 * 2.1.allow
	 * Action=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, resource=mfa/mfa1
	 * 只允许上述对mfa1操作
	 */
	public void test_mfaALLMethod_Allow_Action_mfa1() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Allow_Action_mfa1";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1的mfa1权限
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1,
				403);
		AssertAccessDenyString(user1ListVirtualString, "ListVirtualMFADevices", userName, "mfa/*");
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// user2无权限
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		devicePair = AssertcreateVirtualMFADevice(root.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		authenticationCode = CreateIdentifyingCode(devicePair.second());
		authenticationCode11 = authenticationCode.first();
		authenticationCode12 = authenticationCode.second();
		String user2CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user2accessKey, user2secretKey,
				MFADeviceName, 403);
		AssertAccessDenyString(user2CreateString, "CreateVirtualMFADevice", user2Name, "mfa/" + MFADeviceName);
		String user2EnableString = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user2EnableString, "EnableMFADevice", user2Name, "user/" + userName);
		String user2DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user2DeactivateString, "DeactivateMFADevice", user2Name, "user/" + userName);
		String user2ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey,
				403);
		AssertAccessDenyString(user2ListVirtualString, "ListVirtualMFADevices", user2Name, "mfa/*");
		String user2ListString = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 403);
		AssertAccessDenyString(user2ListString, "ListMFADevices", user2Name, "user/" + user2Name);
		String user2DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user2DeleteString, "DeleteVirtualMFADevice", user2Name, "mfa/" + MFADeviceName);

		// user1无其他mfa权限
		String user1CreateString2 = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName2, 403);
		AssertAccessDenyString(user1CreateString2, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName2);

		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();

		String user1EnableString2 = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName2, authenticationCode21, authenticationCode22, 403);
		AssertAccessDenyString(user1EnableString2, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString2 = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName2, 403);
		AssertAccessDenyString(user1DeactivateString2, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListVirtualString2 = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1,
				403);
		AssertAccessDenyString(user1ListVirtualString2, "ListVirtualMFADevices", userName, "mfa/*");
		String user1ListString2 = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString2, "ListMFADevices", userName, "user/" + userName);
		String user1DeleteString2 = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2, 403);
		AssertAccessDenyString(user1DeleteString2, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName2);

	}

	@Test
	/*
	 * 2.2.allow
	 * Action=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, resource=mfa/*
	 * 允许上述对mfa操作
	 */
	public void test_mfaALLMethod_Allow_Action_mfaAll() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Allow_Action_mfaAll";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1的mfa1权限
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1,
				200);
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// user2无权限
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		devicePair = AssertcreateVirtualMFADevice(root.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		authenticationCode = CreateIdentifyingCode(devicePair.second());
		authenticationCode11 = authenticationCode.first();
		authenticationCode12 = authenticationCode.second();
		String user2CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user2accessKey, user2secretKey,
				MFADeviceName, 403);
		AssertAccessDenyString(user2CreateString, "CreateVirtualMFADevice", user2Name, "mfa/" + MFADeviceName);
		String user2EnableString = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user2EnableString, "EnableMFADevice", user2Name, "user/" + userName);
		String user2DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user2DeactivateString, "DeactivateMFADevice", user2Name, "user/" + userName);
		String user2ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey,
				403);
		AssertAccessDenyString(user2ListVirtualString, "ListVirtualMFADevices", user2Name, "mfa/*");
		String user2ListString = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 403);
		AssertAccessDenyString(user2ListString, "ListMFADevices", user2Name, "user/" + user2Name);
		String user2DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user2DeleteString, "DeleteVirtualMFADevice", user2Name, "mfa/" + MFADeviceName);

		// user1有所有mfa权限
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();

		String user1EnableString2 = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName2, authenticationCode21, authenticationCode22, 403);
		AssertAccessDenyString(user1EnableString2, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString2 = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName2, 403);
		AssertAccessDenyString(user1DeactivateString2, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListVirtualString2 = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1,
				200);
		String user1ListString2 = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString2, "ListMFADevices", userName, "user/" + userName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 2.3.allow
	 * Action=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, resource=*
	 * 允许上述对mfa操作
	 */
	public void test_mfaALLMethod_Allow_Action_ALL() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Allow_Action_ALL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1的mfa1权限
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// user2无权限
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		devicePair = AssertcreateVirtualMFADevice(root.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		authenticationCode = CreateIdentifyingCode(devicePair.second());
		authenticationCode11 = authenticationCode.first();
		authenticationCode12 = authenticationCode.second();
		String user2CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user2accessKey, user2secretKey,
				MFADeviceName, 403);
		AssertAccessDenyString(user2CreateString, "CreateVirtualMFADevice", user2Name, "mfa/" + MFADeviceName);
		String user2EnableString = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user2EnableString, "EnableMFADevice", user2Name, "user/" + userName);
		String user2DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user2DeactivateString, "DeactivateMFADevice", user2Name, "user/" + userName);
		String user2ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey,
				403);
		AssertAccessDenyString(user2ListVirtualString, "ListVirtualMFADevices", user2Name, "mfa/*");
		String user2ListString = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 403);
		AssertAccessDenyString(user2ListString, "ListMFADevices", user2Name, "user/" + user2Name);
		String user2DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user2DeleteString, "DeleteVirtualMFADevice", user2Name, "mfa/" + MFADeviceName);

		// user1有所有mfa权限
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 2.4.allow
	 * Action=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, resource=group/*
	 * 资源不匹配，策略失效
	 */
	public void test_mfaALLMethod_Allow_Action_resourceNotMatch() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Allow_Action_resourceNotMatch";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1因为资源不匹配，无权限
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		AssertAccessDenyString(user1CreateString, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1,
				403);
		AssertAccessDenyString(user1ListVirtualString, "ListVirtualMFADevices", userName, "mfa/*");
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeleteString, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName);

	}

	@Test
	/*
	 * 2.5.allow
	 * Action=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices,
	 * NotResource=mfa/mfa1 允许所有操作，但资源是非mfa/mfa1
	 */
	public void test_mfaALLMethod_Allow_Action_Notmfa1() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Allow_Action_Notmfa1";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1的mfa1权限
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		AssertAccessDenyString(user1CreateString, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeleteString, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName);

		// user2无权限
		String user2CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user2accessKey, user2secretKey,
				MFADeviceName, 403);
		AssertAccessDenyString(user2CreateString, "CreateVirtualMFADevice", user2Name, "mfa/" + MFADeviceName);
		String user2EnableString = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user2EnableString, "EnableMFADevice", user2Name, "user/" + userName);
		String user2DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user2DeactivateString, "DeactivateMFADevice", user2Name, "user/" + userName);
		String user2ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey,
				403);
		AssertAccessDenyString(user2ListVirtualString, "ListVirtualMFADevices", user2Name, "mfa/*");
		String user2ListString = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 403);
		AssertAccessDenyString(user2ListString, "ListMFADevices", user2Name, "user/" + user2Name);
		String user2DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user2DeleteString, "DeleteVirtualMFADevice", user2Name, "mfa/" + MFADeviceName);

		// user1无其他mfa权限
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 2.6.allow
	 * Action=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, NotResource=mfa/*
	 * 允许所有操作，但策略是非mfa/*
	 */
	public void test_mfaALLMethod_Allow_Action_NotmfaAll() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Allow_Action_NotmfaAll";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1允许非mfa操作
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		AssertAccessDenyString(user1CreateString, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		String user1ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1,
				403);
		AssertAccessDenyString(user1ListVirtualString, "ListVirtualMFADevices", userName, "mfa/*");
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeleteString, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName);

	}

	@Test
	/*
	 * 2.7.allow
	 * Action=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, NotResource=*
	 * 允许所有操作，但策略是非*
	 */
	public void test_mfaALLMethod_Allow_Action_NotAll() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Allow_Action_NotmfaAll";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1允许非*操作
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		AssertAccessDenyString(user1CreateString, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1,
				403);
		AssertAccessDenyString(user1ListVirtualString, "ListVirtualMFADevices", userName, "mfa/*");
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeleteString, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName);

	}

	@Test
	/*
	 * 2.8.allow
	 * NotAction=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, Resource=mfa/mfa1
	 * 匹配除了上述操作之外的mfa1操作
	 */
	public void test_mfaALLMethod_Allow_NotAction_mfa1() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Allow_NotAction_mfa1";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1允许非*操作
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		AssertAccessDenyString(user1CreateString, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1,
				403);
		AssertAccessDenyString(user1ListVirtualString, "ListVirtualMFADevices", userName, "mfa/*");
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeleteString, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		// 验证 除了 上述接口，其他跟mfa相关的接口都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("CreateVirtualMFADevice");
		excludes.add("EnableMFADevice");
		excludes.add("DeactivateMFADevice");
		excludes.add("ListVirtualMFADevices");
		excludes.add("ListMFADevices");
		excludes.add("DeleteVirtualMFADevice");

		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName);
	}

	@Test
	/*
	 * 2.9.allow
	 * NotAction=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, Resource=mfa/*
	 * 匹配除了上述操作之外的mfa1操作
	 */
	public void test_mfaALLMethod_Allow_NotAction_mfaAll() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Allow_NotAction_mfaAll";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1拒绝上述操作
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		AssertAccessDenyString(user1CreateString, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1,
				403);
		AssertAccessDenyString(user1ListVirtualString, "ListVirtualMFADevices", userName, "mfa/*");
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeleteString, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		// 验证 除了 上述接口，其他跟mfa相关的接口都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("CreateVirtualMFADevice");
		excludes.add("EnableMFADevice");
		excludes.add("DeactivateMFADevice");
		excludes.add("ListVirtualMFADevices");
		excludes.add("ListMFADevices");
		excludes.add("DeleteVirtualMFADevice");

		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, accountId, MFADeviceName);

	}

	@Test
	/*
	 * 2.10.allow
	 * NotAction=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, Resource=*
	 * 匹配除了上述操作之外的mfa1操作
	 */
	public void test_mfaALLMethod_Allow_NotAction_ALL() {
		// 创建policy
		String policyName = "test_mfaALLMethod_NotAllow_NotAction_ALL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1拒绝上述操作
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		AssertAccessDenyString(user1CreateString, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1,
				403);
		AssertAccessDenyString(user1ListVirtualString, "ListVirtualMFADevices", userName, "mfa/*");
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeleteString, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		// 验证 除了 上述接口，其他跟mfa相关的接口都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("CreateVirtualMFADevice");
		excludes.add("EnableMFADevice");
		excludes.add("DeactivateMFADevice");
		excludes.add("ListVirtualMFADevices");
		excludes.add("ListMFADevices");
		excludes.add("DeleteVirtualMFADevice");
		String policyName2 = "test_policy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateUser"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"lala_1", tags, policyName2, policyString2, accountId, "testGroup88", "mfa2");

	}

	@Test
	/*
	 * 2.11.allow
	 * NotAction=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices,
	 * NotResource=mfa/mfa1 匹配除了上述操作之外的mfa1操作
	 */
	public void test_mfaALLMethod_Allow_NotAction_Notmfa1() {
		// 创建policy
		String policyName = "test_mfaALLMethod_NotAllow_NotAction_Notmfa1";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1拒绝上述操作
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		AssertAccessDenyString(user1CreateString, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1,
				403);
		AssertAccessDenyString(user1ListVirtualString, "ListVirtualMFADevices", userName, "mfa/*");
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeleteString, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		// 验证 除了 上述接口，其他跟mfa相关的接口都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("CreateVirtualMFADevice");
		excludes.add("EnableMFADevice");
		excludes.add("DeactivateMFADevice");
		excludes.add("ListVirtualMFADevices");
		excludes.add("ListMFADevices");
		excludes.add("DeleteVirtualMFADevice");
		String policyName2 = "test_policy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateUser"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		// 资源是mfa1的都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName);
		// 除了上述接口，mfa2可以访问
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"testGroup88", userName, accountId, policyName2, policyString2);
		// 验证 跟policy资源相关接口允许
		String policyName3 = "test_policy2";
		String policyString3 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateUser"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				policyName3, policyString3, accountId);
		// 验证 跟user资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, "lala_2", tags, policyName2, policyString2, accountId);

		// 验证 *资源匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);

	}

	@Test
	/*
	 * 2.12.allow
	 * NotAction=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, NotResource=mfa/*
	 * 匹配除了上述操作之外的mfa1操作
	 */
	public void test_mfaALLMethod_Allow_NotAction_NotmfaALL() {
		// 创建policy
		String policyName = "test_mfaALLMethod_NotAllow_NotAction_NotmfaALL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1拒绝上述操作
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		AssertAccessDenyString(user1CreateString, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1,
				403);
		AssertAccessDenyString(user1ListVirtualString, "ListVirtualMFADevices", userName, "mfa/*");
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeleteString, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		// 验证 除了 上述接口，其他跟mfa相关的接口都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("CreateVirtualMFADevice");
		excludes.add("EnableMFADevice");
		excludes.add("DeactivateMFADevice");
		excludes.add("ListVirtualMFADevices");
		excludes.add("ListMFADevices");
		excludes.add("DeleteVirtualMFADevice");
		String policyName2 = "test_policy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateUser"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		// 资源是mfa1的都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName);
		// 资源是mfa2的都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"testGroup88", userName, accountId, policyName2, policyString2);
		// 验证 跟policy资源相关接口允许
		String policyName3 = "test_policy2";
		String policyString3 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateUser"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				policyName3, policyString3, accountId);
		// 验证 跟user资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, "lala_2", tags, policyName2, policyString2, accountId);

		// 验证 *资源匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);

	}

	@Test
	/*
	 * 2.13.allow
	 * NotAction=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, NotResource=*
	 * 匹配除了上述操作之外 资源非*的操作
	 */
	public void test_mfaALLMethod_Allow_NotAction_NotALL() {
		// 创建policy
		String policyName = "test_mfaALLMethod_NotAllow_NotAction_NotmfaALL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1拒绝上述操作
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		AssertAccessDenyString(user1CreateString, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListVirtualString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1,
				403);
		AssertAccessDenyString(user1ListVirtualString, "ListVirtualMFADevices", userName, "mfa/*");
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeleteString, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName);

		// 验证 除了上述接口，其他跟*的接口都允许
		String policyName2 = "test_policy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateUser"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "lala_3",
				tags, policyName2, policyString2, accountId, "testGroup88", "mfa3");

	}

	@Test
	/*
	 * 2.14.Deny
	 * Action=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, resource=mfa/mfa1
	 * 只允许上述对mfa1操作
	 */
	public void test_mfaALLMethod_Deny_Action_mfa1() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Deny_Action_mfa1";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 创建policy
		String policyName2 = "Allow_group";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1的mfa1权限
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		AssertAccessDenyString(user1CreateString, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeleteString, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		// 验证 除了 上述接口，其他跟mfa相关的接口都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("CreateVirtualMFADevice");
		excludes.add("EnableMFADevice");
		excludes.add("DeactivateMFADevice");
		excludes.add("ListVirtualMFADevices");
		excludes.add("ListMFADevices");
		excludes.add("DeleteVirtualMFADevice");

		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName);

		// user1对mfa2的所有操作权限
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2);
	}

	@Test
	/*
	 * 2.15.Deny
	 * Action=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, resource=mfa/*
	 * 只允许上述对mfa1操作
	 */
	public void test_mfaALLMethod_Deny_Action_mfaAll() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Deny_Action_mfaAll";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 创建policy
		String policyName2 = "Allow_group";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1的mfa1权限
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		AssertAccessDenyString(user1CreateString, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListMFAString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		AssertAccessDenyString(user1ListMFAString, "ListVirtualMFADevices", userName, "mfa/*");
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeleteString, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		// 验证 除了 上述接口，其他跟mfa相关的接口都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("CreateVirtualMFADevice");
		excludes.add("EnableMFADevice");
		excludes.add("DeactivateMFADevice");
		excludes.add("ListVirtualMFADevices");
		excludes.add("ListMFADevices");
		excludes.add("DeleteVirtualMFADevice");

		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName);

		// user1对mfa2的所有操作权限
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2);
	}

	@Test
	/*
	 * 2.16.Deny
	 * Action=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, resource=*
	 * 只允许上述对mfa1操作
	 */
	public void test_mfaALLMethod_Deny_Action_ALL() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Deny_Action_ALL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 创建policy
		String policyName2 = "Allow_group";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1的mfa1权限
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName, 403);
		AssertAccessDenyString(user1CreateString, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListMFAString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		AssertAccessDenyString(user1ListMFAString, "ListVirtualMFADevices", userName, "mfa/*");
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeleteString, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		// 验证 除了 上述接口，其他跟mfa相关的接口都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("CreateVirtualMFADevice");
		excludes.add("EnableMFADevice");
		excludes.add("DeactivateMFADevice");
		excludes.add("ListVirtualMFADevices");
		excludes.add("ListMFADevices");
		excludes.add("DeleteVirtualMFADevice");

		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName);

		// user1对mfa2的所有操作权限
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2);
	}

	@Test
	/*
	 * 2.17.Deny
	 * Action=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, resource=group/*
	 * 资源不匹配 deny失效
	 */
	public void test_mfaALLMethod_Deny_Action_ReourceNotMatch() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Deny_Action_ALL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 创建policy
		String policyName2 = "Allow_group";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// 资源不匹配 deny失败
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListMFAString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 200);

	}

	@Test
	/*
	 * 2.18.Deny
	 * Action=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices,
	 * Notresource=mfa/mfa1 只允许上述对mfa1操作
	 */
	public void test_mfaALLMethod_Deny_Action_Notmfa1() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Deny_Action_Notmfa1";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 创建policy
		String policyName2 = "Allow_group";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1有mfa1的相关权限
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		String user1ListMFAString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		AssertAccessDenyString(user1ListMFAString, "ListVirtualMFADevices", userName, "mfa/*");
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		String user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 200);

		// user1无其他mfa的相关权限
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		devicePair = AssertcreateVirtualMFADevice(root.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode21 = authenticationCode.first();
		String authenticationCode22 = authenticationCode.second();
		String user1CreateString = IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1,
				MFADeviceName2, 403);
		AssertAccessDenyString(user1CreateString, "CreateVirtualMFADevice", userName, "mfa/" + MFADeviceName2);
		user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId,
				MFADeviceName2, authenticationCode21, authenticationCode22, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName2, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		user1ListMFAString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		AssertAccessDenyString(user1ListMFAString, "ListVirtualMFADevices", userName, "mfa/*");
		user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		user1DeleteString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId,
				MFADeviceName2, 403);
		AssertAccessDenyString(user1DeleteString, "DeleteVirtualMFADevice", userName, "mfa/" + MFADeviceName2);
	}

	@Test
	/*
	 * 2.19.Deny
	 * Action=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, Notresource=mfa/*
	 * 只允许上述对mfa1操作
	 */
	public void test_mfaALLMethod_Deny_Action_NotmfaAll() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Deny_Action_NotmfaAll";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 创建policy
		String policyName2 = "Allow_mfa";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1有mfa1的相关权限
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// user1无其他mfa的相关权限
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		root = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		devicePair = AssertcreateVirtualMFADevice(root.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode21 = authenticationCode.first();
		String authenticationCode22 = authenticationCode.second();
		user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId,
				MFADeviceName2, authenticationCode21, authenticationCode22, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName2, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);
	}

	@Test
	/*
	 * 2.20.Deny
	 * Action=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, Notresource=*
	 * 只允许上述对mfa1操作
	 */
	public void test_mfaALLMethod_Deny_Action_NotALL() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Deny_Action_NotALL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 创建policy
		String policyName2 = "Allow_mfa";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		// user1有mfa1的相关权限
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		String user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		String user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// user1无其他mfa的相关权限
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		root = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		devicePair = AssertcreateVirtualMFADevice(root.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode21 = authenticationCode.first();
		String authenticationCode22 = authenticationCode.second();
		user1EnableString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId,
				MFADeviceName2, authenticationCode21, authenticationCode22, 403);
		AssertAccessDenyString(user1EnableString, "EnableMFADevice", userName, "user/" + userName);
		user1DeactivateString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName2, 403);
		AssertAccessDenyString(user1DeactivateString, "DeactivateMFADevice", userName, "user/" + userName);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		user1ListString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		AssertAccessDenyString(user1ListString, "ListMFADevices", userName, "user/" + userName);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);
	}

	@Test
	/*
	 * 2.21.Deny
	 * NotAction=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, resource=mfa/mfa1
	 * 只允许上述对mfa1操作
	 */
	public void test_mfaALLMethod_Deny_NotAction_mfa1() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Deny_NotAction_mfa1";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 创建policy
		String policyName2 = "Allow_group";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证 除了 上述接口，其他跟mfa相关的接口都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("EnableMFADevice");
		excludes.add("DeactivateMFADevice");
		excludes.add("ListVirtualMFADevices");
		excludes.add("ListMFADevices");

		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName);
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2);

	}

	@Test
	/*
	 * 2.22.Deny
	 * NotAction=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, resource=mfa/*
	 * 只允许上述对mfa1操作
	 */
	public void test_mfaALLMethod_Deny_NotAction_mfaAll() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Deny_NotAction_mfaAll";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 创建policy
		String policyName2 = "Allow_group";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证 除了 上述接口，其他跟mfa相关的接口都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("EnableMFADevice");
		excludes.add("DeactivateMFADevice");
		excludes.add("ListVirtualMFADevices");
		excludes.add("ListMFADevices");

		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName);
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2);

	}

	@Test
	/*
	 * 2.23.Deny
	 * NotAction=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, resource=*
	 * 只允许上述对mfa1操作
	 */
	public void test_mfaALLMethod_Deny_NotAction_ALL() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Deny_NotAction_ALL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 创建policy
		String policyName2 = "Allow_group";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 跟mfa相关的接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName);
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2);

	}

	@Test
	/*
	 * 2.24.Deny
	 * NotAction=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices,
	 * Notresource=mfa/mfa1 只允许上述对mfa1操作
	 */
	public void test_mfaALLMethod_Deny_NotAction_Notmfa1() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Deny_NotAction_Notmfa1";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 创建policy
		String policyName2 = "Allow_group";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证 除了 上述接口，其他跟mfa相关的接口都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("EnableMFADevice");
		excludes.add("DeactivateMFADevice");
		excludes.add("ListVirtualMFADevices");
		excludes.add("ListMFADevices");

		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName);
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2);

	}

	@Test
	/*
	 * 2.25.Deny
	 * NotAction=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, Notresource=mfa/*
	 * 只允许上述对mfa1操作
	 */
	public void test_mfaALLMethod_Deny_NotAction_NotmfaAll() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Deny_NotAction_NotmfaAll";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 创建policy
		String policyName2 = "Allow_group";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证 除了 上述接口，其他跟mfa相关的接口都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("EnableMFADevice");
		excludes.add("DeactivateMFADevice");
		excludes.add("ListVirtualMFADevices");
		excludes.add("ListMFADevices");

		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName);
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2);

	}

	@Test
	/*
	 * 2.26.Deny
	 * NotAction=CreateVirtualMFADevice,DeleteVirtualMFADevice,EnableMFADevice,
	 * DeactivateMFADevice, ListVirtualMFADevices,ListMFADevices, Notresource=*
	 * 只允许上述对mfa1操作
	 */
	public void test_mfaALLMethod_Deny_NotAction_NotALL() {
		// 创建policy
		String policyName = "test_mfaALLMethod_Deny_NotAction_NotALL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 创建policy
		String policyName2 = "Allow_group";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证 除了 上述接口，其他跟mfa相关的接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName);
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2);

	}

	@Test
	/*
	 * 2.a.在IP范围的允许访问
	 */
	public void test_mfaALLMethod_Condition_sourceIP() {
		String MFADeviceName = "testMFADevice01";
		String userName = user1Name;
		String policyName = "allowspecialIP";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.168.1.1/24")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 在IP范围
		String body1 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body1, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		String body2 = "Action=EnableMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber) + "&AuthenticationCode1=" + authenticationCode11
				+ "&AuthenticationCode2=" + authenticationCode12;
		String body3 = "Action=DeactivateMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber);
		String body4 = "Action=ListVirtualMFADevices&Version=2010-05-08";
		String body5 = "Action=ListMFADevices&Version=2010-05-08&UserName=" + userName;
		String body6 = "Action=DeleteVirtualMFADevice&SerialNumber=" + UrlEncoded.encodeString(serialNumber);
		List<Pair<String, String>> params = new ArrayList<Pair<String, String>>();
		Pair<String, String> param1 = new Pair<String, String>();
		param1.first("X-Forwarded-For");
		param1.second("192.168.1.101");
		params.add(param1);

		Pair<Integer, String> enableresult = IAMTestUtils.invokeHttpsRequest2(body2, user1accessKey1, user1secretKey1,
				params);
		assertEquals(200, enableresult.first().intValue());

		Pair<Integer, String> Deactivateresult = IAMTestUtils.invokeHttpsRequest2(body3, user1accessKey1,
				user1secretKey1, params);
		assertEquals(200, Deactivateresult.first().intValue());

		Pair<Integer, String> ListVirtual = IAMTestUtils.invokeHttpsRequest2(body4, user1accessKey1, user1secretKey1,
				params);
		assertEquals(200, ListVirtual.first().intValue());

		Pair<Integer, String> list = IAMTestUtils.invokeHttpsRequest2(body5, user1accessKey1, user1secretKey1, params);
		assertEquals(200, list.first().intValue());

		Pair<Integer, String> deletemfa = IAMTestUtils.invokeHttpsRequest2(body6, user1accessKey1, user1secretKey1,
				params);
		assertEquals(200, deletemfa.first().intValue());

		// 不在IP范围
		List<Pair<String, String>> params2 = new ArrayList<Pair<String, String>>();
		Pair<String, String> param2 = new Pair<String, String>();
		param2.first("X-Forwarded-For");
		param2.second("192.168.2.101");
		params2.add(param2);

		body1 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		root = IAMTestUtils.invokeHttpsRequest(body1, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		devicePair = AssertcreateVirtualMFADevice(root.second(), "arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		authenticationCode = CreateIdentifyingCode(devicePair.second());
		authenticationCode11 = authenticationCode.first();
		authenticationCode12 = authenticationCode.second();

		Pair<Integer, String> enableresult2 = IAMTestUtils.invokeHttpsRequest2(body2, user1accessKey1, user1secretKey1,
				params2);
		assertEquals(403, enableresult2.first().intValue());
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);

		Pair<Integer, String> Deactivateresult2 = IAMTestUtils.invokeHttpsRequest2(body3, user1accessKey1,
				user1secretKey1, params2);
		assertEquals(403, Deactivateresult2.first().intValue());
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);

		Pair<Integer, String> ListVirtual2 = IAMTestUtils.invokeHttpsRequest2(body4, user1accessKey1, user1secretKey1,
				params2);
		assertEquals(403, ListVirtual2.first().intValue());

		Pair<Integer, String> list2 = IAMTestUtils.invokeHttpsRequest2(body5, user1accessKey1, user1secretKey1,
				params2);
		assertEquals(403, list2.first().intValue());

		Pair<Integer, String> deletemfa2 = IAMTestUtils.invokeHttpsRequest2(body6, user1accessKey1, user1secretKey1,
				params2);
		assertEquals(403, deletemfa2.first().intValue());

	}

	@Test
	/*
	 * 2.b.username允许访问
	 */
	public void test_mfaALLMethod_Condition_username() {
		String MFADeviceName = "testMFADevice01";
		String userName = user1Name;
		String policyName = "allowsuser";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);

		String body1 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body1, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		String body2 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body2, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.EnableMFADevice(user3accessKey, user3secretKey, userName, accountId, MFADeviceName,
				authenticationCode21, authenticationCode22, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user3accessKey, user3secretKey, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user3accessKey, user3secretKey, 403);
		IAMInterfaceTestUtils.ListMFADevices(user3accessKey, user3secretKey, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user3accessKey, user3secretKey, accountId, MFADeviceName, 403);
	}

	@Test
	/*
	 * 2.c.符合时间条件允许访问
	 */
	public void test_mfaALLMethod_Condition_CurrentTime() {
		String MFADeviceName = "testMFADevice01";
		String userName = user1Name;
		String policyName = "allowDateGreate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2019-01-01T00:00:00Z")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);

		// 时间符合条件
		String body1 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body1, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2050-01-01T00:00:00Z")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 时间不符合条件
		String body2 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body2, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.EnableMFADevice(user3accessKey, user3secretKey, userName, accountId, MFADeviceName,
				authenticationCode21, authenticationCode22, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user3accessKey, user3secretKey, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user3accessKey, user3secretKey, 403);
		IAMInterfaceTestUtils.ListMFADevices(user3accessKey, user3secretKey, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user3accessKey, user3secretKey, accountId, MFADeviceName, 403);
	}

	@Test
	/*
	 * 2.d.允许或者拒绝SSL
	 */
	public void test_GroupALLMethod_Condition_SecureTransport() {
		String MFADeviceName = "testMFADevice01";
		String userName = user1Name;
		String policyName = "DenySSL";

		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);

		// 允许ssl访问
		String body1 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body1, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("false")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 不允许ssl访问
		String body2 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body2, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.EnableMFADevice(user3accessKey, user3secretKey, userName, accountId, MFADeviceName,
				authenticationCode21, authenticationCode22, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user3accessKey, user3secretKey, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user3accessKey, user3secretKey, 403);
		IAMInterfaceTestUtils.ListMFADevices(user3accessKey, user3secretKey, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user3accessKey, user3secretKey, accountId, MFADeviceName, 403);
	}

	@Test
	/*
	 * 3.1.一个policy 两个statement allow Action 所有mfa action方法 deny mfa1
	 * deleteVirtualMFADevice deactivateMFADevice
	 */
	public void test_OnePolicyTwoStatement_AllowAndDeny1() {
		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";
		String userName = user1Name;
		// 创建policy
		String policyName = "TwoState";
		List<Statement> statements = new ArrayList<Statement>();
		Statement s1 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		statements.add(s1);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		Statement s2 = IAMTestUtils.CreateStatement(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice", "iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName), conditions);
		statements.add(s2);
		String policyString = IAMTestUtils.CreateMoreStatement(statements);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户组添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName, 200);

		// user1拒绝删除和Deactivate
		String body1 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body1, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		// IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName,
		// accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		String body2 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body2, user1accessKey1, user1secretKey1);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				403);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

		// user3不符合test*,拒绝失效
		String body3 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root3 = IAMTestUtils.invokeHttpsRequest(body3, user3accessKey, user3secretKey);
		assertEquals(200, root3.first().intValue());
		Pair<String, String> devicePair3 = AssertcreateVirtualMFADevice(root3.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode3 = CreateIdentifyingCode(devicePair3.second());
		String authenticationCode31 = authenticationCode3.first();
		String authenticationCode32 = authenticationCode3.second();
		IAMInterfaceTestUtils.EnableMFADevice(user3accessKey, user3secretKey, userName, accountId, MFADeviceName,
				authenticationCode31, authenticationCode32, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user3accessKey, user3secretKey, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user3accessKey, user3secretKey, 200);
		IAMInterfaceTestUtils.ListMFADevices(user3accessKey, user3secretKey, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user3accessKey, user3secretKey, accountId, MFADeviceName, 200);

	}

	@Test
	/*
	 * 3.2.一个policy 两个statement allow Action 所有mfa action方法 deny
	 * deleteVirtualMFADevice deactivateMFADevice
	 */
	public void test_OnePolicyTwoStatement_AllowAndDeny2() {
		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";
		String userName = user1Name;
		// 创建policy
		String policyName = "TwoState";
		List<Statement> statements = new ArrayList<Statement>();
		Statement s1 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:EnableMFADevice",
						"iam:DeactivateMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		statements.add(s1);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		Statement s2 = IAMTestUtils.CreateStatement(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice", "iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions);
		statements.add(s2);
		String policyString = IAMTestUtils.CreateMoreStatement(statements);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户组添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName, 200);

		// user1拒绝删除和Deactivate
		String body1 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body1, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		// IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName,
		// accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		// user3不符合test*,拒绝失效
		String body3 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root3 = IAMTestUtils.invokeHttpsRequest(body3, user3accessKey, user3secretKey);
		assertEquals(200, root3.first().intValue());
		Pair<String, String> devicePair3 = AssertcreateVirtualMFADevice(root3.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode3 = CreateIdentifyingCode(devicePair3.second());
		String authenticationCode31 = authenticationCode3.first();
		String authenticationCode32 = authenticationCode3.second();
		IAMInterfaceTestUtils.EnableMFADevice(user3accessKey, user3secretKey, userName, accountId, MFADeviceName2,
				authenticationCode31, authenticationCode32, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user3accessKey, user3secretKey, userName, accountId, MFADeviceName2,
				403);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user3accessKey, user3secretKey, 200);
		IAMInterfaceTestUtils.ListMFADevices(user3accessKey, user3secretKey, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user3accessKey, user3secretKey, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 3.3. 一个policy 两个statement allow NotAction CreateVirtualMFADevice allow Action
	 * CreateVirtualMFADevice mfa1 匹配test*
	 */
	public void test_OnePolicyTwoStatement_AllowAllow1() {
		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";
		String userName = user1Name;
		// 创建policy
		String policyName = "test_AllowAllow1";
		List<Statement> statements = new ArrayList<Statement>();
		Statement s1 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		statements.add(s1);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		Statement s2 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName), conditions);
		statements.add(s2);
		String policyString = IAMTestUtils.CreateMoreStatement(statements);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName, 200);

		// user1允许mfa1
		String body1 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body1, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// user1不允许mfa2
		String body2 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body2, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				403);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

		// user3不允许mfa1
		String body3 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root3 = IAMTestUtils.invokeHttpsRequest(body3, accessKey, secretKey);
		assertEquals(200, root3.first().intValue());
		Pair<String, String> devicePair3 = AssertcreateVirtualMFADevice(root3.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode3 = CreateIdentifyingCode(devicePair3.second());
		String authenticationCode31 = authenticationCode3.first();
		String authenticationCode32 = authenticationCode3.second();
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user3accessKey, user3secretKey, MFADeviceName, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user3accessKey, user3secretKey, userName, accountId, MFADeviceName,
				authenticationCode31, authenticationCode32, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user3accessKey, user3secretKey, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user3accessKey, user3secretKey, 200);
		IAMInterfaceTestUtils.ListMFADevices(user3accessKey, user3secretKey, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user3accessKey, user3secretKey, accountId, MFADeviceName, 200);

	}

	@Test
	/*
	 * 3.4.一个policy 两个statement allow NotAction CreateVirtualMFADevice allow Action
	 * CreateVirtualMFADevice 匹配test*
	 */
	public void test_OnePolicyTwoStatement_AllowAllow2() {
		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";
		String userName = user1Name;
		// 创建policy
		String policyName = "test_AllowAllow2";
		List<Statement> statements = new ArrayList<Statement>();
		Statement s1 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		statements.add(s1);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		Statement s2 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions);
		statements.add(s2);
		String policyString = IAMTestUtils.CreateMoreStatement(statements);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName, 200);

		// user1允许mfa1
		String body1 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body1, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// user1允许mfa2
		String body2 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body2, user1accessKey1, user1secretKey1);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				403);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

		// user3不允许mfa1
		String body3 = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root3 = IAMTestUtils.invokeHttpsRequest(body3, accessKey, secretKey);
		assertEquals(200, root3.first().intValue());
		Pair<String, String> devicePair3 = AssertcreateVirtualMFADevice(root3.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode3 = CreateIdentifyingCode(devicePair3.second());
		String authenticationCode31 = authenticationCode3.first();
		String authenticationCode32 = authenticationCode3.second();
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user3accessKey, user3secretKey, MFADeviceName, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user3accessKey, user3secretKey, userName, accountId, MFADeviceName,
				authenticationCode31, authenticationCode32, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user3accessKey, user3secretKey, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user3accessKey, user3secretKey, 200);
		IAMInterfaceTestUtils.ListMFADevices(user3accessKey, user3secretKey, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user3accessKey, user3secretKey, accountId, MFADeviceName, 200);

	}

	@Test
	/*
	 * 3.5.两个允许policy
	 */
	public void test_TwoPolicy_AllowAllow1() {
		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";
		String userName = user1Name;

		String policyName = "test_TwoPolicy_AllowAllow1-1";
		String policyName2 = "test_TwoPolicy_AllowAllow1-2";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName2), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName2, 200);

		// user1可创建mfa1 mfa2
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		// user3可创建mfa2 不可创建mfa1
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user3accessKey, user3secretKey, MFADeviceName, 403);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user3accessKey, user3secretKey, MFADeviceName2, 200);
	}

	// =======================DeleteVirtualMFADevice==============================================
	@Test
	/*
	 * 1.allow Action=DeleteVirtualMFADevice, resource=mfa/mfaDevice1
	 * 只允许删除mfa/mfaDevice1
	 */
	public void test_DeleteVirtualMFADevice_Allow_Action_MFADevice1() throws JSONException {
		// 创建policy
		String policyName = "DeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testVirtualMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testVirtualMFADevice01";
		String MFADeviceName2 = "testVirtualMFADevice02";
		// 首先用root创建一个mfaDevice
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		// 验证请求
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// user2无权限删除
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		String user2xmlString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		// user1无权限删除mfaDevice2
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		String user1bxmlString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

	}

	@Test
	/*
	 * 2.allow Action=DeleteVirtualMFADevice, resource=mfa/* 可以删除所有MFADevice
	 */
	public void test_DeleteVirtualMFADevice_Allow_Action_all() throws JSONException {
		// 创建policy
		String policyName = "DeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testVirtualMFADevice01";
		String MFADeviceName2 = "testVirtualMFADevice02";
		// 首先用root创建一个mfaDevice
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		// 验证请求
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// user2无权限删除
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		String user2xmlString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		// user1可以删除mfaDevice2
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 3.allow Action=DeleteVirtualMFADevice, resource=* 可以删除所有MFADevice
	 */
	public void test_DeleteVirtualMFADevice_Allow_Action_all2() throws JSONException {
		// 创建policy
		String policyName = "DeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testVirtualMFADevice01";
		String MFADeviceName2 = "testVirtualMFADevice02";
		// 首先用root创建一个mfaDevice
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		// 验证请求
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// user2无权限删除
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		String user2xmlString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId,
				MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		// user1可以删除mfaDevice2
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * a.allow Action=DeleteVirtualMFADevice, resource=user/*
	 * 资源和请求的action不匹配，policy不生效
	 */
	public void test_DeleteVirtualMFADevice_Allow_Action_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyName = "DeleteVirtualMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		String MFADeviceName = "testVirtualMFADevice01";
		String MFADeviceName2 = "testVirtualMFADevice02";

		// 验证请求
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=DeleteVirtualMFADevice&SerialNumber=" + UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, user1.first().intValue());
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1.second());
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		body = "Action=DeleteVirtualMFADevice&SerialNumber=" + UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> user2 = IAMTestUtils.invokeHttpsRequest(body, user2accessKey, user2secretKey);
		assertEquals(403, user2.first().intValue());
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2.second());
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName2;
		body = "Action=DeleteVirtualMFADevice&SerialNumber=" + UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> user1b = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, user1b.first().intValue());
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(user1b.second());
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error3.get("Message"));
		assertEquals("/", error3.get("Resource"));
	}

	@Test
	/*
	 * 4.allow NotAction=DeleteVirtualMFADevice, resource=mfa/mfaDevice1
	 * 资源resource只能匹配除了DeleteVirtualMFADevice的其他MFADevice相关操作
	 */
	public void test_DeleteVirtualMFADevice_Allow_NotAction_mfaDevice1() throws JSONException {
		// 创建策略
		String policyName = "DeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给用户添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// user1删除MFADevice1 MFADevice2 都不允许
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		String deleteMFADevice1String = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deleteMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		String deleteMFADevice2String = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deleteMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		// 验证 除了DeleteVirtualMFADevice其他跟mfa/mfaDevice1相关的方法都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("DeleteVirtualMFADevice");
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				accountId, MFADeviceName);
		// 和资源不匹配的mfaDevice2不允许
		IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user1accessKey1, user1secretKey1, accountId,
				MFADeviceName2);

		// listVirtualMFADevices, resource not match
		body = "Action=ListVirtualMFADevices&Version=2010-05-08";
		Pair<Integer, String> MFADeviceslist = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, MFADeviceslist.first().intValue());
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(MFADeviceslist.second());
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error3.get("Message"));
		assertEquals("/", error3.get("Resource"));
		// user1 ListMFADevices, resource not match
		body = "Action=ListMFADevices&Version=2010-05-08&UserName=" + userName;
		Pair<Integer, String> MFADeviceslist2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, MFADeviceslist2.first().intValue());
		JSONObject error4 = IAMTestUtils.ParseErrorToJson(MFADeviceslist2.second());
		assertEquals("AccessDenied", error4.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error4.get("Message"));
		assertEquals("/", error4.get("Resource"));

		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyName, policyString, accountId);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"lala_1", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 5.allow NotAction=CreateVirtualMFADevice, resource=mfa/*
	 * 资源resource只能匹配除了CreateVirtualMFADevice的其他VirtualMFADevice相关操作
	 */
	public void test_DeleteVirtualMFADevice_Allow_NotAction_mfaDeviceall() throws JSONException {
		//
		String policyName = "DeleteVirtualMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证user1删除VirtualMFADevice1 VirtualMFADevice2都不允许
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		String deleteMFADevice1String = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deleteMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String deleteMFADevice2String = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deleteMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		// 验证 除了 DeleteVirtualMFADevice其他跟mfa/*相关的方法都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("DeleteVirtualMFADevice");
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, accountId, MFADeviceName);

		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyName, policyString, accountId);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"test_11", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 6.allow NotAction=DeleteVirtualMFADevice, resource=*
	 * 可匹配除了DeleteVirtualMFADevice的所有其他操作
	 */
	public void test_DeleteVirtualMFADevice_Allow_NotAction_all() throws JSONException {
		// 创建策略
		String userName = "test_1";
		String policyName = "DeleteVirtualMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给用户添加policy
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证user1删除VirtualMFADevice1 VirtualMFADevice2都不允许
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		String deleteMFADevice1String = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deleteMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String deleteMFADevice2String = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deleteMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		// 验证 除了 DeleteVirtualMFADevice所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("DeleteVirtualMFADevice");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "DeleteVirtualMFADevicePolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "group1", "mfa2");
	}

	@Test
	/*
	 * 7.allow Action=DeleteVirtualMFADevice, NotResource=mfaDevice/mfaDevice1
	 * 允许DeleteVirtualMFADevice 但是资源是非mfaDevice/mfaDevice1
	 */
	public void test_DeleteVirtualMFADevice_Allow_Action_NotmfaDevice1() throws JSONException {
		// 创建policy
		String policyName = "DeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		String deleteMFADeviceString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deleteMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);
	}

	@Test
	/*
	 * 8.allow Action=DeleteVirtualMFADevice, NotResource=mfa/*
	 * 允许DeleteVirtualMFADevice 但是资源是非mfa/*
	 */
	public void test_DeleteVirtualMFADevice_Allow_Action_NotmfaDeviceALL() throws JSONException {
		// 创建policy
		String policyName = "DeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		String deleteMFADeviceString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deleteMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		String deleteMFADeviceString2 = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deleteMFADeviceString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
	}

	@Test
	/*
	 * 9.allow Action=DeleteVirtualMFADevice, NotResource:* 允许DeleteVirtualMFADevice
	 * 但是资源是非*
	 */
	public void test_DeleteVirtualMFADevice_Allow_Action_NotALL() throws JSONException {
		// 创建policy
		String policyName = "DeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		String deleteMFADeviceString = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deleteMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		String deleteMFADeviceString2 = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1,
				accountId, MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deleteMFADeviceString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
	}

	@Test
	/*
	 * 10.allow NotAction=DeleteVirtualMFADevice, NotResource=mfaDevice/mfaDevice1
	 * 允许非DeleteVirtualMFADevice 但是资源是非mfaDevice/mfaDevice1
	 */
	public void test_DeleteVirtualMFADevice_Allow_NotAction_NotmfaDevice1() throws JSONException {
		// 创建policy
		String policyName = "DeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证删除mfaDevice1 和mfaDevice2都不允许
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		String deleteMFADevice1String = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey,
				accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deleteMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		String deleteMFADevice2String = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey,
				accountId, MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deleteMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		// 资源为mfaDevice/mfaDevice1的是都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user2accessKey, user2secretKey, accountId,
				MFADeviceName);
		// listVirtualMFADevices,允许
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 200);
		// user1 ListMFADevices, 允许
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, userName, 200);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				policyName1, policyString1, accountId);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey, null);

	}

	@Test
	/*
	 * 11.allow NotAction=DeleteVirtualMFADevice, NotResource=mfa/*
	 * 允许非DeleteVirtualMFADevice 但是资源是非mfa/*
	 */
	public void test_DeleteVirtualMFADevice_Allow_NotAction_NotmfaALL() throws JSONException {
		// 创建policy
		String policyName = "DeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证删除group1 和group2都不允许
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		String deleteMFADevice1String = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey,
				accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deleteMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		String deleteMFADevice2String = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey,
				accountId, MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deleteMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		// 验证资源是mfa/*的都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user2accessKey, user2secretKey, accountId,
				MFADeviceName);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				policyName1, policyString1, accountId);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey, null);
	}

	@Test
	/*
	 * 12.allow NotAction=DeleteVirtualMFADevice, NotResource=*
	 * 允许非DeleteVirtualMFADevice 但是资源是非*
	 */
	public void test_DeleteVirtualMFADevice_Allow_NotAction_NotALL() throws JSONException {
		// 创建policy
		String policyName = "DeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证删除group1 和group2都不允许
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		String deleteMFADevice1String = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey,
				accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deleteMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		String deleteMFADevice2String = IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey,
				accountId, MFADeviceName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deleteMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeleteVirtualMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName2 + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21",
				tags, policyName, policyString, accountId, "group1", "mfa3");
	}

	@Test
	/*
	 * 13.Deny Action=DeleteVirtualMFADevice, resource=mfa/mfaDevice1
	 * 显示拒绝删除mfaDevice1
	 */
	public void test_DeleteVirtualMFADevice_Deny_Action_mfaDevice1() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeleteMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限删除mfaDevice，但有权限create(enable,list资源不匹配)
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

	}

	@Test
	/*
	 * 14.Deny Action=DeleteVirtualMFADevice, resource=mfa/*
	 */
	public void test_DeleteVirtualMFADevice_Deny_Action_mfaall() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeleteMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限删除mfaDevice，但有权限create和list
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
	}

	@Test
	/*
	 * 15.Deny Action=DeleteVirtualMFADevice, resource=*
	 */
	public void test_DeleteVirtualMFADevice_Deny_Action_all() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeleteMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(
				Effect.Allow, null, null, "Action", Arrays.asList("iam:CreateVirtualMFADevice",
						"iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices", "iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限删除mfaDevice，但有权限create和list
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
	}

	@Test
	/*
	 * b.Deny Action=DeleteVirtualMFADevice, resource=user/* 资源不匹配，deny失败
	 */
	public void test_DeleteVirtualMFADevice_Deny_Action_ReourceNotMatch() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝资源不匹配未生效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeleteMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝未生效，有显示允许，user1可以create，delete和list,但不能listMFADevices(这个资源匹配上了)
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);
	}

	@Test
	/*
	 * 16.Deny Action=DeleteVirtualMFADevice, NotResource=mfa/mfaDevice1
	 * 资源非mfaDevice1,显示拒绝mfaDevice1失效，显示拒绝mfaDevice2生效
	 */
	public void test_DeleteVirtualMFADevice_Deny_Action_NotResouce_mfa1() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		String policyName2 = "AllowDeleteMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝mfaDevice1失效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// 显示拒绝mfaDevice2生效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 403);

	}

	@Test
	/*
	 * 17.Deny Action=DeleteVirtualMFADevice, NotResource=mfa/*
	 */
	public void test_DeleteVirtualMFADevice_Deny_Action_NotResouce_mfaAll() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		String policyName2 = "AllowDeleteMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝mfaDevice1失效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// 显示拒绝mfaDevice2失效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 18.Deny Action=DeleteVirtualMFADevice, NotResource=*
	 */
	public void test_DeleteVirtualMFADevice_Deny_Action_NotResouce_All() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		String policyName2 = "AllowDeleteMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝mfaDevice1失效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// 显示拒绝mfaDevice2失效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 19.Deny NotAction=DeleteVirtualMFADevice, Resource=mfa/mfaDevice1
	 */
	public void test_DeleteVirtualMFADevice_Deny_NotAction_Resource_mfa1() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝删除设备
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		String policyName2 = "AllowDeleteMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝除删除以外的方法，Enable和Deactivate因为资源匹配不上而不允许
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, user1.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(user1.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// 显示拒绝mfaDevice2失效
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> user1b = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1b.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(user1b.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 20.Deny NotAction=DeleteVirtualMFADevice, Resource=mfa/*
	 */
	public void test_DeleteVirtualMFADevice_Deny_NotAction_Resource_mfaAll() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		String policyName2 = "AllowDeleteMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝除删除以外的方法
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// 显示拒绝除删除以外的方法
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 403);
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> rootb = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, rootb.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(rootb.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);
	}

	@Test
	/*
	 * 21.Deny NotAction=DeleteVirtualMFADevice, Resource=*
	 */
	public void test_DeleteVirtualMFADevice_Deny_NotAction_Resource_All() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝删除设备
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		String policyName2 = "AllowDeleteMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝除删除以外的方法
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// 显示拒绝除删除以外的方法
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 403);
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> rootb = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, rootb.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(rootb.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 22.Deny NotAction=DeleteVirtualMFADevice, NotResource=mfa/mfaDevice1
	 */
	public void test_DeleteVirtualMFADevice_Deny_NotAction_NotResource_mfa1() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/testMFADevice01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝删除设备
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		String policyName2 = "AllowDeleteMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// mfaDevice1的操作都允许
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(user1.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);

		// mfaDevice2除delete以外都拒绝
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 403);
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> user1b = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, user1b.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(user1b.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 403);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				403);
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 23.Deny NotAction=DeleteVirtualMFADevice, NotResource=mfa/*
	 */
	public void test_DeleteVirtualMFADevice_Deny_NotAction_NotResource_mfaAll() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		String policyName2 = "AllowDeleteMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// mfaDevice1的操作除了delete以外都拒绝，前提是resource不匹配mfa/*
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(user1.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// mfaDevice2除delete以外都拒绝
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> user1b = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1b.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(user1b.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 403);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				403);
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 24.Deny NotAction=DeleteVirtualMFADevice, NotResource=*
	 */
	public void test_DeleteVirtualMFADevice_Deny_NotAction_NotResource_All() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeleteMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		String policyName2 = "AllowDeleteMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 都允许
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(user1.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// mfaDevice2除delete以外都拒绝
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> user1b = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1b.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(user1b.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode21, authenticationCode22, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * c.在IP范围的允许访问
	 */
	public void test_DeleteVirtualMFADevice_Condition_sourceIP() {
		String userName = user1Name;
		String policyName = "allowspecialIP";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.168.1.1/24")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 在IP范围
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		String body = "Action=DeleteVirtualMFADevice&SerialNumber=" + UrlEncoded.encodeString(serialNumber);
		List<Pair<String, String>> params = new ArrayList<Pair<String, String>>();
		Pair<String, String> param1 = new Pair<String, String>();
		param1.first("X-Forwarded-For");
		param1.second("192.168.1.101");
		params.add(param1);

		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1, params);
		assertEquals(200, result.first().intValue());

		// 不在IP范围
		List<Pair<String, String>> params2 = new ArrayList<Pair<String, String>>();
		Pair<String, String> param2 = new Pair<String, String>();
		param2.first("X-Forwarded-For");
		param2.second("192.168.2.101");
		params2.add(param2);

		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,
				params2);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * d.符合username匹配允许访问
	 */
	public void test_DeleteVirtualMFADevice_Condition_username() {
		String userName = "test_1";
		String policyName = "allowUsername";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// username 符合条件
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		String body = "Action=DeleteVirtualMFADevice&SerialNumber=" + UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		// username 不符合条件
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName2;
		body = "Action=DeleteVirtualMFADevice&SerialNumber=" + UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(body, user3accessKey, user3secretKey);
		assertEquals(403, result3.first().intValue());
	}

	@Test
	/*
	 * e.符合实际条件允许访问
	 */
	public void test_DeleteVirtualMFADevice_Condition_CurrentTime() {
		String userName = "test_1";
		String policyName = "allowDateGreate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2019-01-01T00:00:00Z")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 时间符合条件
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		String body = "Action=DeleteVirtualMFADevice&SerialNumber=" + UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2050-01-01T00:00:00Z")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 时间不符合条件
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * f.设置不允许ssl访问
	 */
	public void test_DeleteVirtualMFADevice_Condition_SecureTransport() {
		String userName = "test_1";
		String policyName = "DenySSL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 允许ssl访问
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		String body = "Action=DeleteVirtualMFADevice&SerialNumber=" + UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("false")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 不允许ssl访问
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName2, 200);
		serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName2;
		body = "Action=DeleteVirtualMFADevice&SerialNumber=" + UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());

	}

	// ==========================EnableMFADevice==================================================
	@Test
	/*
	 * 1.allow Action=enableMFADevice, resource=user/user1 只允许user1来enable MFADevice
	 */
	public void test_EnableMFADevice_Allow_Action_user1() throws JSONException {
		// 创建policy
		String policyName = "enableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testVirtualMFADevice01";
		String MFADeviceName2 = "testVirtualMFADevice02";
		// 首先由root创建MFADevice1, MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());

		// 验证请求
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode1 = authenticationCode.first();
		String authenticationCode2 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode1, authenticationCode2, 200);
		// root解除enable
		body = "Action=DeactivateMFADevice&Version=2010-05-08&SerialNumber=" + "arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + "&UserName=" + userName;
		Pair<Integer, String> user1deactivateMFADevice = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, user1deactivateMFADevice.first().intValue());

		// user2不能enable MFADevice
		String user2xmlString = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, authenticationCode1, authenticationCode2, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error.get("Message"));
		assertEquals("test_2", error.get("Resource"));

		// user1可以enable MFADevice2
		Pair<String, String> devicePairb = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCodeb = CreateIdentifyingCode(devicePairb.second());
		authenticationCode1 = authenticationCodeb.first();
		authenticationCode2 = authenticationCodeb.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode1, authenticationCode2, 200);

	}

	@Test
	/*
	 * 2.allow Action=enableMFADevice, resource=user/* 所有user都可以enable MFADevice
	 */
	public void test_EnableMFADevice_Allow_Action_all() throws JSONException {
		// 创建policy
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testVirtualMFADevice01";
		String MFADeviceName2 = "testVirtualMFADevice02";
		// 首先由root创建MFADevice1, MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());

		// 验证请求
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode1 = authenticationCode.first();
		String authenticationCode2 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode1, authenticationCode2, 200);
		// root解除enable
		body = "Action=DeactivateMFADevice&Version=2010-05-08&SerialNumber=" + "arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + "&UserName=" + userName;
		Pair<Integer, String> user1deactivateMFADevice = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, user1deactivateMFADevice.first().intValue());

		// user2不能enable MFADevice1
		String user2xmlString = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, authenticationCode1, authenticationCode2, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error.get("Message"));
		assertEquals("test_2", error.get("Resource"));

		// user1可以enable MFADevice2
		Pair<String, String> devicePairb = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCodeb = CreateIdentifyingCode(devicePairb.second());
		authenticationCode1 = authenticationCodeb.first();
		authenticationCode2 = authenticationCodeb.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode1, authenticationCode2, 200);

	}

	@Test
	/*
	 * 3.allow Action=enableMFADevice, resource=* 所有user可以enable
	 * MFADevice，和resource=user/*相同意义
	 */
	public void test_EnableMFADevice_Allow_Action_all2() throws JSONException {
		// 创建policy
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testVirtualMFADevice01";
		String MFADeviceName2 = "testVirtualMFADevice02";
		// 首先由root创建MFADevice1, MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());

		// 验证请求
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode1 = authenticationCode.first();
		String authenticationCode2 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode1, authenticationCode2, 200);
		// root解除enable
		body = "Action=DeactivateMFADevice&Version=2010-05-08&SerialNumber=" + "arn:ctyun:iam::3rmoqzn03g6ga:mfa/"
				+ MFADeviceName + "&UserName=" + userName;
		Pair<Integer, String> user1deactivateMFADevice = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, user1deactivateMFADevice.first().intValue());

		// user2不能enable MFADevice
		String user2xmlString = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, authenticationCode1, authenticationCode2, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error.get("Message"));
		assertEquals("test_2", error.get("Resource"));

		// user1可以enable MFADevice2
		Pair<String, String> devicePairb = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCodeb = CreateIdentifyingCode(devicePairb.second());
		authenticationCode1 = authenticationCodeb.first();
		authenticationCode2 = authenticationCodeb.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName2,
				authenticationCode1, authenticationCode2, 200);

	}

	@Test
	/*
	 * a.allow Action=EnableMFADevice, resource=mfa/* 资源和请求的action不匹配，policy不生效
	 */
	public void test_EnableMFADevice_Allow_Action_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 首先创建MFADevice
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();

		// 验证请求
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=EnableMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber) + "&AuthenticationCode1=" + authenticationCode11
				+ "&AuthenticationCode2=" + authenticationCode12;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, user1.first().intValue());
		JSONObject error0 = IAMTestUtils.ParseErrorToJson(user1.second());
		assertEquals("AccessDenied", error0.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/test_1.",
				error0.get("Message"));
		assertEquals("test_1", error0.get("Resource"));

		serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=EnableMFADevice&Version=2010-05-08&UserName=" + user2Name + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber) + "&AuthenticationCode1=" + authenticationCode11
				+ "&AuthenticationCode2=" + authenticationCode12;
		Pair<Integer, String> user2 = IAMTestUtils.invokeHttpsRequest(body, user2accessKey, user2secretKey);
		assertEquals(403, user2.first().intValue());
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2.second());
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error.get("Message"));
		assertEquals("test_2", error.get("Resource"));

		serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName2;
		body = "Action=EnableMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber) + "&AuthenticationCode1=" + authenticationCode11
				+ "&AuthenticationCode2=" + authenticationCode12;
		Pair<Integer, String> user1b = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, user1b.first().intValue());
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1b.second());
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/test_1.",
				error2.get("Message"));
		assertEquals("test_1", error2.get("Resource"));
	}

	@Test
	/*
	 * 4.allow NotAction=EnableMFADevice, resource=user/user1
	 * 资源resource只能匹配除了EnableMFADevice的其他MFADevice相关操作
	 */
	public void test_EnableMFADevice_Allow_NotAction_mfaDevice1() throws JSONException {
		// 创建策略
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给user1、user2添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());
		String bodyAttach2 = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + user2Name + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(bodyAttach2, accessKey, secretKey);
		assertEquals(200, result3.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		// user1启动MFADevice1 MFADevice2 都不允许
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName2, authenticationCode21, authenticationCode22, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error2.get("Message"));
		assertEquals("test_1", error2.get("Resource"));
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		// 验证 除了EnableMFADevice其他跟user/user1相关的方法都允许
		List<String> excludes = new ArrayList<String>();
		IAMInterfaceTestUtils.AllowActionResourceMFA_userResource(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, accountId, MFADeviceName);
		// 和资源不匹配的user2不允许
		IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user2accessKey, user2secretKey, accountId,
				MFADeviceName);

		// listVirtualMFADevices, resource not match
		body = "Action=ListVirtualMFADevices&Version=2010-05-08";
		Pair<Integer, String> MFADeviceslist = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, MFADeviceslist.first().intValue());
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(MFADeviceslist.second());
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error3.get("Message"));
		assertEquals("/", error3.get("Resource"));

		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyName, policyString, accountId);
		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 5.allow NotAction=EnableMFADevice, resource=user/*
	 * 资源resource只能匹配除了EnableMFADevice的其他user相关操作
	 */
	public void test_EnableMFADevice_Allow_NotAction_userall() throws JSONException {
		//
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给user1、user2添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());
		String bodyAttach2 = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + user2Name + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(bodyAttach2, accessKey, secretKey);
		assertEquals(200, result3.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		// user1启动MFADevice1 MFADevice2 都不允许
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName2, authenticationCode21, authenticationCode22, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error2.get("Message"));
		assertEquals("test_1", error2.get("Resource"));
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		// 验证 除了 EnableMFADevice其他跟user/*相关的方法都允许
		List<String> excludes = new ArrayList<String>();
		IAMInterfaceTestUtils.AllowActionResourceMFAALL_userResource(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, accountId, MFADeviceName);

		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyName, policyString, accountId);
		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 6.allow NotAction=EnableMFADevice, resource=* 可匹配除了EnableMFADevice的所有其他操作
	 */
	public void test_EnableMFADevice_Allow_NotAction_all() throws JSONException {
		// 创建策略
		String userName = "test_1";
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:EnableMFADevice"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给用户添加policy
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());
		String bodyAttach2 = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + user2Name + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(bodyAttach2, accessKey, secretKey);
		assertEquals(200, result3.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		// user1启动MFADevice1 MFADevice2 都不允许
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName2, authenticationCode21, authenticationCode22, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error2.get("Message"));
		assertEquals("test_1", error2.get("Resource"));
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		// 验证 除了 EnableMFADevice所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("EnableMFADevice");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "DeleteVirtualMFADevicePolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:EnableMFADevice"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "group1", "mfa2");
	}

	@Test
	/*
	 * 7.allow Action=EnableMFADevice, NotResource=user/user1 
	 * 允许EnableMFADevice 但是资源是非user/user1
	 */
	public void test_EnableMFADevice_Allow_Action_NotUser1() throws JSONException {
		// 创建policy
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String enableMFADeviceString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));

		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
	}

	@Test
	/*
	 * 8.allow Action=EnableMFADevice, NotResource=user/* 
	 * 允许EnableMFADevice 但是资源是非user/*
	 */
	public void test_EnableMFADevice_Allow_Action_NotUserALL() throws JSONException {
		// 创建policy
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String enableMFADeviceString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));

		String enableMFADeviceString2 = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADeviceString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
	}

	@Test
	/*
	 * 9.allow Action=EnableMFADevice, NotResource:* 允许EnableMFADevice 但是资源是非*
	 */
	public void test_EnableMFADevice_Allow_Action_NotALL() throws JSONException {
		// 创建policy
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String enableMFADeviceString = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));

		String enableMFADeviceString2 = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADeviceString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));

	}

	@Test
	/*
	 * 10.allow NotAction=EnableMFADevice, NotResource=user/user1 允许非EnableMFADevice
	 * 但是资源是非user/user1
	 */
	public void test_EnableMFADevice_Allow_NotAction_NotUser1() throws JSONException {
		// 创建policy
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:EnableMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		// user2启动MFADevice1 MFADevice2 都不允许
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_2", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, userName,
				accountId, MFADeviceName2, authenticationCode21, authenticationCode22, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		// listVirtualMFADevices,允许
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 200);
		// user2 ListMFADevices, 允许
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, userName, 200);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				policyName1, policyString1, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey, null);

	}

	@Test
	/*
	 * 11.allow NotAction=EnableMFADevice, NotResource=user/* 允许非EnableMFADevice
	 * 但是资源是非user/*
	 */
	public void test_EnableMFADevice_Allow_NotAction_NotUserALL() throws JSONException {
		// 创建policy
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:EnableMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		// user2启动MFADevice1 MFADevice2 都不允许
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_2", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, userName,
				accountId, MFADeviceName2, authenticationCode21, authenticationCode22, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				policyName1, policyString1, accountId);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user2accessKey, user2secretKey, "lala_18",
				tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey, null);
	}

	@Test
	/*
	 * 12.allow NotAction=EnableMFADevice, NotResource=* 允许非EnableMFADevice 但是资源是非*
	 */
	public void test_EnableMFADevice_Allow_NotAction_NotALL() throws JSONException {
		// 创建policy
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:EnableMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		// user2启动MFADevice1 MFADevice2 都不允许
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, userName,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_2", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, userName,
				accountId, MFADeviceName2, authenticationCode21, authenticationCode22, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName2, 200);
        //其他都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21",
				tags, policyName, policyString, accountId, "group1", "mfa3");
	}

	@Test
	/*
	 * 13.Deny Action=EnableMFADevice, resource=user/user1 显示拒绝
	 */
	public void test_EnableMFADevice_Deny_Action_mfaDevice1() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));

		String policyName2 = "AllowEnableMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限enable，但有权限list, deactivate
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);

	}

	@Test
	/*
	 * 14.Deny Action=EnableMFADevice, resource=user/*
	 */
	public void test_EnableMFADevice_Deny_Action_userall() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyEnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));

		String policyName2 = "AllowEnableMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限enable，但有权限list, deactivate
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
	}

	@Test
	/*
	 * 15.Deny Action=EnableMFADevice, resource=*
	 */
	public void test_EnableMFADevice_Deny_Action_all() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyEnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));

		String policyName2 = "AllowEnableMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限enable，但有权限create, delete, list, deactivate
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
	}

	@Test
	/*
	 * b.Deny Action=EnableMFADevice, resource=mfa/* 资源不匹配，deny失败
	 */
	public void test_EnableMFADevice_Deny_Action_ReourceNotMatch() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyEnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝资源不匹配未生效
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));

		String policyName2 = "AllowEnableMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝未生效，有显示允许，user1可以enable,list(resource不匹配),可以create,delete(action不匹配)
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
	}

	@Test
	/*
	 * 16.Deny Action=EnableMFADevice, NotResource=user/user1
	 * 资源非user1,显示拒绝user1失效，显示拒绝user2生效
	 */
	public void test_EnableMFADevice_Deny_Action_NotResouce_user1() throws JSONException { 
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyEnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName2;
		Pair<Integer, String> root2 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root2.first().intValue());
		Pair<String, String> devicePair2 = AssertcreateVirtualMFADevice(root2.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName2);
		Pair<String, String> authenticationCode2 = CreateIdentifyingCode(devicePair2.second());
		String authenticationCode21 = authenticationCode2.first();
		String authenticationCode22 = authenticationCode2.second();
		// 一个隐式拒绝，一个显式拒绝
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));

		String policyName2 = "AllowEnableMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝user1失效
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);

		// 显示拒绝user2生效
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);

	}

	@Test
	/*
	 * 17.Deny Action=EnableMFADevice, NotResource=user/*
	 */
	public void test_EnableMFADevice_Deny_Action_NotResouce_userAll() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyEnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// 拒绝
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));

		String policyName2 = "AllowEnableMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝user1失效
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		// 显示拒绝user2失效
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
	}

	@Test
	/*
	 * 18.Deny Action=EnableMFADevice, NotResource=*
	 */
	public void test_EnableMFADevice_Deny_Action_NotResouce_All() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyEnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// 隐式拒绝
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));

		String policyName2 = "AllowEnableMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝user1失效
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		// 显示拒绝user2失效
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);

	}

	@Test
	/*
	 * 19.Deny NotAction=EnableMFADevice, Resource=user/user1
	 */
	public void test_EnableMFADevice_Deny_NotAction_Resource_user1() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyEnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// user1 user2启动MFADevice1都不允许
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));

		String policyName2 = "AllowEnableMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除enable以外的方法
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

		// 显示拒绝user2失效
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 403);

	}

	@Test
	/*
	 * 20.Deny NotAction=EnableMFADevice, Resource=user/*
	 */
	public void test_EnableMFADevice_Deny_NotAction_Resource_userAll() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyEnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// user1 user2启动MFADevice1都不允许
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));

		String policyName2 = "AllowEnableMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除enable以外的方法
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		// IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1,
		// user1secretKey1, accountId, MFADeviceName, 200);

		// 显示拒绝除enable以外的方法
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 200);
	}

	@Test
	/*
	 * 21.Deny NotAction=EnableMFADevice, Resource=*
	 */
	public void test_EnableMFADevice_Deny_NotAction_Resource_All() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyEnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:EnableMFADevice"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// user1 user2启动MFADevice1都不允许
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));

		String policyName2 = "AllowEnableMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除enable以外的方法
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

		// 显示拒绝除enable以外的方法
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 403);

	}

	@Test
	/*
	 * 22.Deny NotAction=EnableMFADevice, NotResource=user/user1
	 */
	public void test_EnableMFADevice_Deny_NotAction_NotResource_user1() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyEnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:EnableMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// user1 user2启动MFADevice1都不允许
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));

		String policyName2 = "AllowEnableMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// user1的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

		// user2的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 403);

	}

	@Test
	/*
	 * 23.Deny NotAction=EnableMFADevice, NotResource=user/*
	 */
	public void test_EnableMFADevice_Deny_NotAction_NotResource_userAll() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyEnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:EnableMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// user1 user2启动MFADevice1都不允许
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));

		String policyName2 = "AllowEnableMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// user1的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

		// user2的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 403);

	}

	@Test
	/*
	 * 24.Deny NotAction=EnableMFADevice, NotResource=*
	 */
	public void test_EnableMFADevice_Deny_NotAction_NotResource_All() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyEnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:EnableMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// user1 user2启动MFADevice1都不允许
		String enableMFADevice1String = IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, authenticationCode11, authenticationCode12, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:EnableMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));

		String policyName2 = "AllowEnableMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// user1的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		// IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1,
		// user1secretKey1, accountId, MFADeviceName, 200);

		// user2的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 200);
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 200);

	}

	@Test
	/*
	 * c.在IP范围的允许访问
	 */
	public void test_EnableMFADevice_Condition_sourceIP() {
		String userName = user1Name;
		String policyName = "allowspecialIP";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.168.1.1/24")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 在IP范围
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=EnableMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber) + "&AuthenticationCode1=" + authenticationCode11
				+ "&AuthenticationCode2=" + authenticationCode12;
		List<Pair<String, String>> params = new ArrayList<Pair<String, String>>();
		Pair<String, String> param1 = new Pair<String, String>();
		param1.first("X-Forwarded-For");
		param1.second("192.168.1.101");
		params.add(param1);

		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1, params);
		assertEquals(200, result.first().intValue());
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);

		// 不在IP范围
		List<Pair<String, String>> params2 = new ArrayList<Pair<String, String>>();
		Pair<String, String> param2 = new Pair<String, String>();
		param2.first("X-Forwarded-For");
		param2.second("192.168.2.101");
		params2.add(param2);

		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,
				params2);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * d.符合username匹配允许访问
	 */
	public void test_EnableMFADevice_Condition_username() {
		String userName = "test_1";
		String policyName = "allowUsername";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// username 符合条件
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=EnableMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber) + "&AuthenticationCode1=" + authenticationCode11
				+ "&AuthenticationCode2=" + authenticationCode12;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);

		// username 不符合条件
		serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=EnableMFADevice&Version=2010-05-08&UserName=" + user3Name + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber) + "&AuthenticationCode1=" + authenticationCode11
				+ "&AuthenticationCode2=" + authenticationCode12;
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(body, user3accessKey, user3secretKey);
		assertEquals(403, result3.first().intValue());
	}

	@Test
	/*
	 * e.符合实际条件允许访问
	 */
	public void test_EnableMFADevice_Condition_CurrentTime() {
		String userName = "test_1";
		String policyName = "allowDateGreate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2019-01-01T00:00:00Z")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 时间符合条件
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=EnableMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber) + "&AuthenticationCode1=" + authenticationCode11
				+ "&AuthenticationCode2=" + authenticationCode12;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);

		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2050-01-01T00:00:00Z")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 时间不符合条件
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * f.设置不允许ssl访问
	 */
	public void test_EnableMFADevice_Condition_SecureTransport() {
		String userName = "test_1";
		String policyName = "DenySSL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 允许ssl访问
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=EnableMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber) + "&AuthenticationCode1=" + authenticationCode11
				+ "&AuthenticationCode2=" + authenticationCode12;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);

		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("false")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:EnableMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 不允许ssl访问
		serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=EnableMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber) + "&AuthenticationCode1=" + authenticationCode11
				+ "&AuthenticationCode2=" + authenticationCode12;
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());

	}

	// ==========================DeactivateMFADevice==============================================
	@Test
	/*
	 * 1.allow Action=DeactivateMFADevice, resource=user/user1
	 * 只允许user1来DeactivateMFADevice
	 */
	public void test_DeactivateMFADevice_Allow_Action_user1() throws JSONException {
		// 创建policy
		String policyName = "DeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testVirtualMFADevice01";
		String MFADeviceName2 = "testVirtualMFADevice02";

		// 首先由root创建MFADevice1
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();

		// 验证请求
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);

		// user2不能Deactivate MFADevice
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String user2xmlString = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name,
				accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error.get("Message"));
		assertEquals("test_2", error.get("Resource"));

	}

	@Test
	/*
	 * 2.allow Action=DeactivateMFADevice, resource=user/*
	 * 所有user都可以DeactivateMFADevice
	 */
	public void test_DeactivateMFADevice_Allow_Action_all() throws JSONException {
		// 创建policy
		String policyName = "DeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testVirtualMFADevice01";
		String MFADeviceName2 = "testVirtualMFADevice02";

		// 首先由root创建MFADevice1
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();

		// 验证请求
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);

		// user2也可以Deactivate MFADevice
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);

	}

	@Test
	/*
	 * 3.allow Action=DeactivateMFADevice, resource=*
	 * 所有user可以DeactivateMFADevice，和resource=user/*相同意义
	 */
	public void test_DeactivateMFADevice_Allow_Action_all2() throws JSONException {
		// 创建policy
		String policyName = "DeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testVirtualMFADevice01";
		String MFADeviceName2 = "testVirtualMFADevice02";

		// 首先由root创建MFADevice1
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();

		// 验证请求
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);

		// user2也可以Deactivate MFADevice
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);

	}

	@Test
	/*
	 * a.allow Action=DeactivateMFADevice, resource=mfa/* 资源和请求的action不匹配，policy不生效
	 */
	public void test_DeactivateMFADevice_Allow_Action_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyName = "DeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());
		String bodyAttach2 = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + user2Name + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(bodyAttach2, accessKey, secretKey);
		assertEquals(200, result3.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 首先由root创建MFADevice1
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();

		// 验证请求
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=DeactivateMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, user1.first().intValue());
		JSONObject error0 = IAMTestUtils.ParseErrorToJson(user1.second());
		assertEquals("AccessDenied", error0.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/test_1.",
				error0.get("Message"));
		assertEquals("test_1", error0.get("Resource"));

		body = "Action=DeactivateMFADevice&Version=2010-05-08&UserName=" + user2Name + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> user2 = IAMTestUtils.invokeHttpsRequest(body, user2accessKey, user2secretKey);
		assertEquals(403, user2.first().intValue());
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2.second());
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error.get("Message"));
		assertEquals("test_2", error.get("Resource"));

	}

	@Test
	/*
	 * 4.allow NotAction=DeactivateMFADevice, resource=user/user1
	 * 资源resource只能匹配除了DeactivateMFADevice的其他user相关操作
	 */
	public void test_DeactivateMFADevice_Allow_NotAction_user1() throws JSONException {
		// 创建策略
		String policyName = "DeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给user1、user2添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());
		String bodyAttach2 = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + user2Name + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(bodyAttach2, accessKey, secretKey);
		assertEquals(200, result3.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);

		// user1、user2禁用MFADevice1都不允许
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				user2Name, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deactivateMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		// 验证 除了DeactivateMFADevice其他跟user/user1相关的方法都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("DeactivateMFADevice");
		IAMInterfaceTestUtils.AllowActionResourceMFA_userResource(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, accountId, MFADeviceName);
		// 和资源不匹配的user2不允许
		IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user2accessKey, user2secretKey, accountId,
				MFADeviceName);

		// listVirtualMFADevices, resource not match
		body = "Action=ListVirtualMFADevices&Version=2010-05-08";
		Pair<Integer, String> MFADeviceslist = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, MFADeviceslist.first().intValue());
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(MFADeviceslist.second());
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error3.get("Message"));
		assertEquals("/", error3.get("Resource"));

		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyName, policyString, accountId);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"lala_1", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 5.allow NotAction=DeactivateMFADevice, resource=user/*
	 * 资源resource只能匹配除了DeactivateMFADevicee的其他user相关操作
	 */
	public void test_DeactivateMFADevice_Allow_NotAction_userall() throws JSONException {
		//
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给user1、user2添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());
		String bodyAttach2 = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + user2Name + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(bodyAttach2, accessKey, secretKey);
		assertEquals(200, result3.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);

		// user1、user2禁用MFADevice1都不允许
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				user2Name, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deactivateMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		// 验证 除了 DeactivateMFADevice其他跟user/*相关的方法都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("DeactivateMFADevice");
		IAMInterfaceTestUtils.AllowActionResourceMFAALL_userResource(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, accountId, MFADeviceName);

		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 6.allow NotAction=DeactivateMFADevice, resource=*
	 * 可匹配除了DeactivateMFADevice的所有其他操作
	 */
	public void test_DeactivateMFADevice_Allow_NotAction_all() throws JSONException {
		// 创建策略
		String userName = "test_1";
		String policyName = "DeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给用户添加policy
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());
		String bodyAttach2 = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + user2Name + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(bodyAttach2, accessKey, secretKey);
		assertEquals(200, result3.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1
		body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);

		// user1、user2禁用MFADevice1都不允许
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				user2Name, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deactivateMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		// 验证 除了DeactivateMFADevice所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("DeactivateMFADevice");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "DeactivateMFADevicePolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "group1", "mfa2");
	}

	@Test
	/*
	 * 7.allow Action=DeactivateMFADevice, NotResource=user/user1
	 * 允许DeactivateMFADevice 但是资源是非user/user1
	 */
	public void test_DeactivateMFADevice_Allow_Action_NotUser1() throws JSONException {
		// 创建policy
		String policyName = "DeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADeviceString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));

		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);
	}

	@Test
	/*
	 * 8.allow Action=DeactivateMFADevice, NotResource=user/* 允许DeactivateMFADevice
	 * 但是资源是非user/*
	 */
	public void test_DeactivateMFADevice_Allow_Action_NotUserALL() throws JSONException {
		// 创建policy
		String policyName = "DeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADeviceString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));

		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADeviceString1 = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				user2Name, accountId, MFADeviceName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(deactivateMFADeviceString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error1.get("Message"));
		assertEquals("test_2", error1.get("Resource"));
	}

	@Test
	/*
	 * 9.allow Action=DeactivateMFADevice, NotResource:* 允许DeactivateMFADevice
	 * 但是资源是非*
	 */
	public void test_DeactivateMFADevice_Allow_Action_NotALL() throws JSONException {
		// 创建policy
		String policyName = "DeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADeviceString = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));

		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADeviceString1 = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				user2Name, accountId, MFADeviceName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(deactivateMFADeviceString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error1.get("Message"));
		assertEquals("test_2", error1.get("Resource"));

	}

	@Test
	/*
	 * 10.allow NotAction=DeactivateMFADevice, NotResource=user/user2
	 * 允许非DeactivateMFADevice 但是资源是非user/user2
	 */
	public void test_DeactivateMFADevice_Allow_NotAction_NotUser1() throws JSONException {
		// 创建policy
		String policyName = "DeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeactivateMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_2"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// user1、user2禁用MFADevice1都不允许
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user1Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String enableMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				user1Name, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user1Name + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user1Name, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String enableMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				userName, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		// listVirtualMFADevices,允许
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 200);
		// user1 ListMFADevices, 允许
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, userName, 403);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				policyName1, policyString1, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey, null);

	}

	@Test
	/*
	 * 11.allow NotAction=DeactivateMFADevice, NotResource=user/*
	 * 允许非DeactivateMFADevice 但是资源是非user/*
	 */
	public void test_DeactivateMFADevice_Allow_NotAction_NotUserALL() throws JSONException {
		// 创建policy
		String policyName = "DeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeactivateMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// user1、user2禁用MFADevice1都不允许
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user1Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String enableMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				user1Name, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user1Name + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user1Name, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String enableMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				userName, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				policyName1, policyString1, accountId);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user2accessKey, user2secretKey, "lala_18",
				tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey, null);
	}

	@Test
	/*
	 * 12.allow NotAction=DeactivateMFADevice, NotResource=* 允许非DeactivateMFADevice
	 * 但是资源是非*
	 */
	public void test_DeactivateMFADevice_Allow_NotAction_NotALL() throws JSONException {
		// 创建policy
		String policyName = "DeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeactivateMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1 MFADevice2
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// user1、user2禁用MFADevice1都不允许
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user1Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String enableMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				user1Name, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(enableMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user1Name + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user1Name, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String enableMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				userName, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(accessKey, secretKey, accountId, MFADeviceName, 200);

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21",
				tags, policyName, policyString, accountId, "group1", "mfa3");
	}

	@Test
	/*
	 * 13.Deny Action=DeactivateMFADevice, resource=user/user1 显示拒绝
	 */
	public void test_DeactivateMFADevice_Deny_Action_user1() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeactivateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝优先，user1没有权限Deactivate，但有权限list, enable,user2可以deactivate
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);

	}

	@Test
	/*
	 * 14.Deny Action=DeactivateMFADevice, resource=user/*
	 */
	public void test_DeactivateMFADevice_Deny_Action_userall() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeactivateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝优先，user1没有权限deactivate，但有权限list, enable, user2相同
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				403);

	}

	@Test
	/*
	 * 15.Deny Action=DeactivateMFADevice, resource=*
	 */
	public void test_DeactivateMFADevice_Deny_Action_all() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeactivateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝优先，user1没有权限deactivate，但有权限list, enable, user2相同
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				403);
	}

	@Test
	/*
	 * 16.Deny Action=DeactivateMFADevice, NotResource=user/user1
	 * 资源非user1,显示拒绝user1失效，显示拒绝user2生效
	 */
	public void test_DeactivateMFADevice_Deny_Action_NotResouce_user1() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				user2Name, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deactivateMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeactivateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝user1失效
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);

		// 显示拒绝user2生效
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, userName, accountId, MFADeviceName,
				403);

	}

	@Test
	/*
	 * 17.Deny Action=DeactivateMFADevice, NotResource=user/*
	 */
	public void test_DeactivateMFADevice_Deny_Action_NotResouce_userAll() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				user2Name, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deactivateMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeactivateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝user1失效
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);

		// 显示拒绝user2失效
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);

	}

	@Test
	/*
	 * 18.Deny Action=DeactivateMFADevice, NotResource=*
	 */
	public void test_DeactivateMFADevice_Deny_Action_NotResouce_All() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				user2Name, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deactivateMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeactivateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝user1失效
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);

		// 显示拒绝user2失效
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);

	}

	@Test
	/*
	 * 19.Deny NotAction=DeactivateMFADevice, Resource=user/user1
	 */
	public void test_DeactivateMFADevice_Deny_NotAction_Resource_user1() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				user2Name, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deactivateMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeactivateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除DeactivateMFADevice以外的方法
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

		// 显示拒绝user2失效
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 403);

	}

	@Test
	/*
	 * 20.Deny NotAction=DeactivateMFADevice, Resource=user/*
	 */
	public void test_DeactivateMFADevice_Deny_NotAction_Resource_userAll() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				user2Name, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deactivateMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeactivateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除DeactivateMFADevice以外的方法
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		// IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1,
		// user1secretKey1, accountId, MFADeviceName, 200);

		// 显示拒绝除DeactivateMFADevice以外的方法
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 200);
	}

	@Test
	/*
	 * 21.Deny NotAction=DeactivateMFADevice, Resource=*
	 */
	public void test_DeactivateMFADevice_Deny_NotAction_Resource_All() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				user2Name, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deactivateMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeactivateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除DeactivateMFADevice以外的方法
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

		// 显示拒绝除DeactivateMFADevice以外的方法
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 403);
	}

	@Test
	/*
	 * 22.Deny NotAction=DeactivateMFADevice, NotResource=user/user1
	 */
	public void test_DeactivateMFADevice_Deny_NotAction_NotResource_user1() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeactivateMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				user2Name, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deactivateMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeactivateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// user1的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

		// user2的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 403);

	}

	@Test
	/*
	 * 23.Deny NotAction=DeactivateMFADevice, NotResource=user/*
	 */
	public void test_DeactivateMFADevice_Deny_NotAction_NotResource_userAll() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeactivateMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				user2Name, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deactivateMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeactivateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// user1的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

		// user2的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 403);

	}

	@Test
	/*
	 * 24.Deny NotAction=DeactivateMFADevice, NotResource=*
	 */
	public void test_DeactivateMFADevice_Deny_NotAction_NotResource_All() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyDeactivateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeactivateMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 先创建MFADevice1
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice1String = IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1,
				userName, accountId, MFADeviceName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(deactivateMFADevice1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("test_1", error.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String deactivateMFADevice2String = IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey,
				user2Name, accountId, MFADeviceName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(deactivateMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeactivateMFADevice on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("test_2", error2.get("Resource"));
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName, 200);

		String policyName2 = "AllowDeactivateMFADevicePolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// user1的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		// IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1,
		// user1secretKey1, accountId, MFADeviceName, 200);

		// user2的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 200);
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 200);

	}

	@Test
	/*
	 * c.在IP范围的允许访问
	 */
	public void test_DeactivateMFADevice_Condition_sourceIP() {
		String userName = user1Name;
		String policyName = "allowspecialIP";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.168.1.1/24")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 在IP范围
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=DeactivateMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber);
		List<Pair<String, String>> params = new ArrayList<Pair<String, String>>();
		Pair<String, String> param1 = new Pair<String, String>();
		param1.first("X-Forwarded-For");
		param1.second("192.168.1.101");
		params.add(param1);

		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1, params);
		assertEquals(200, result.first().intValue());

		// 不在IP范围
		List<Pair<String, String>> params2 = new ArrayList<Pair<String, String>>();
		Pair<String, String> param2 = new Pair<String, String>();
		param2.first("X-Forwarded-For");
		param2.second("192.168.2.101");
		params2.add(param2);

		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,
				params2);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * d.符合username匹配允许访问
	 */
	public void test_DeactivateMFADevice_Condition_username() {
		String userName = "test_1";
		String policyName = "allowUsername";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// username 符合条件
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=DeactivateMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		// username 不符合条件
		serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=DeactivateMFADevice&Version=2010-05-08&UserName=" + user3Name + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(body, user3accessKey, user3secretKey);
		assertEquals(403, result3.first().intValue());
	}

	@Test
	/*
	 * e.符合实际条件允许访问
	 */
	public void test_DeactivateMFADevice_Condition_CurrentTime() {
		String userName = "test_1";
		String policyName = "allowDateGreate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2019-01-01T00:00:00Z")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 时间符合条件
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=DeactivateMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2050-01-01T00:00:00Z")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 时间不符合条件
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * f.设置不允许ssl访问
	 */
	public void test_DeactivateMFADevice_Condition_SecureTransport() {
		String userName = "test_1";
		String policyName = "DenySSL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 允许ssl访问
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=DeactivateMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("false")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeactivateMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 不允许ssl访问
		serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=DeactivateMFADevice&Version=2010-05-08&UserName=" + userName + "&SerialNumber="
				+ UrlEncoded.encodeString(serialNumber);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());

	}

	// =============================ListMFADevices=================================================
	@Test
	/*
	 * 1.allow Action=ListMFADevices, resource=user/user1 只允许user1来ListMFADevices
	 */
	public void test_ListMFADevices_Allow_Action_user1() throws JSONException {
		// 创建policy
		String policyName = "ListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);

		// user2不能ListMFADevice
		String user2xmlString = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

	}

	@Test
	/*
	 * 2.allow Action=ListMFADevices, resource=user/* 所有user都可以ListMFADevices
	 */
	public void test_ListMFADevices_Allow_Action_all() throws JSONException {
		// 创建policy
		String policyName = "ListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);

		// user2也可以Deactivate MFADevice
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, userName, 200);

	}

	@Test
	/*
	 * 3.allow Action=ListMFADevices, resource=*
	 * 所有user可以ListMFADevices，和resource=user/*相同意义
	 */
	public void test_ListMFADevices_Allow_Action_all2() throws JSONException {
		// 创建policy
		String policyName = "ListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);

		// user2也可以Deactivate MFADevice
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, userName, 200);

	}

	@Test
	/*
	 * a.allow Action=ListMFADevices, resource=mfa/* 资源和请求的action不匹配，policy不生效
	 */
	public void test_ListMFADevices_Allow_Action_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyName = "ListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());
		String bodyAttach2 = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + user2Name + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(bodyAttach2, accessKey, secretKey);
		assertEquals(200, result3.first().intValue());

		// 验证请求
		String user1xmlString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String user2xmlString = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

	}

	@Test
	/*
	 * 4.allow NotAction=ListMFADevices, resource=user/user1
	 * 资源resource只能匹配除了ListMFADevices的其他user相关操作
	 */
	public void test_ListMFADevices_Allow_NotAction_user1() throws JSONException {
		// 创建策略
		String policyName = "ListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给user1、user2添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());
		String bodyAttach2 = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + user2Name + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(bodyAttach2, accessKey, secretKey);
		assertEquals(200, result3.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// user1、user2 ListMFADevices都不允许
		String user1xmlString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String user2xmlString = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		// 验证 除了ListMFADevices其他跟user/user1相关的方法都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("ListMFADevices");
		IAMInterfaceTestUtils.AllowActionResourceMFA_userResource(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, accountId, MFADeviceName);
		// 和资源不匹配的user2不允许
		IAMInterfaceTestUtils.DenyActionResourceMFA(accessKey, secretKey, user2accessKey, user2secretKey, accountId,
				MFADeviceName);

		// listVirtualMFADevices, resource not match
		body = "Action=ListVirtualMFADevices&Version=2010-05-08";
		Pair<Integer, String> MFADeviceslist = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, MFADeviceslist.first().intValue());
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(MFADeviceslist.second());
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error3.get("Message"));
		assertEquals("/", error3.get("Resource"));

		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyName, policyString, accountId);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"lala_1", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 5.allow NotAction=ListMFADevices, resource=user/*
	 * 资源resource只能匹配除了ListMFADevices的其他user相关操作
	 */
	public void test_ListMFADevices_Allow_NotAction_userall() throws JSONException {
		//
		String policyName = "ListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给user1、user2添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());
		String bodyAttach2 = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + user2Name + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(bodyAttach2, accessKey, secretKey);
		assertEquals(200, result3.first().intValue());

		// MFADevice1
		String MFADeviceName = "testVirtualMFADevice01";

		// user1、user2 ListMFADevice都不允许
		String user1xmlString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String user2xmlString = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		// 验证 除了 ListMFADevices其他跟user/*相关的方法都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("ListMFADevices");
		IAMInterfaceTestUtils.AllowActionResourceMFAALL_userResource(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, accountId, MFADeviceName);

		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 6.allow NotAction=ListMFADevices, resource=* 可匹配除了ListMFADevices的所有其他操作
	 */
	public void test_ListMFADevices_Allow_NotAction_all() throws JSONException {
		// 创建策略
		String userName = "test_1";
		String policyName = "ListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListMFADevices"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给用户添加policy
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());
		String bodyAttach2 = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + user2Name + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(bodyAttach2, accessKey, secretKey);
		assertEquals(200, result3.first().intValue());

		// user1、user2 ListMFADevice都不允许
		String user1xmlString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String user2xmlString = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		// 验证 除了ListMFADevices所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("ListMFADevices");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "ListMFADevicesPolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListMFADevices"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "group1", "mfa2");
	}

	@Test
	/*
	 * 7.allow Action=ListMFADevices, NotResource=user/user1 允许ListMFADevices
	 * 但是资源是非user/user1
	 */
	public void test_ListMFADevices_Allow_Action_NotUser1() throws JSONException {
		// 创建policy
		String policyName = "ListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		// 验证请求
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 200);
	}

	@Test
	/*
	 * 8.allow Action=ListMFADevices, NotResource=user/* 允许ListMFADevices
	 * 但是资源是非user/*
	 */
	public void test_ListMFADevices_Allow_Action_NotUserALL() throws JSONException {
		// 创建policy
		String policyName = "ListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		// 验证请求
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String listMFADeviceString2 = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listMFADeviceString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
	}

	@Test
	/*
	 * 9.allow Action=ListMFADevices, NotResource:* 允许ListMFADevices 但是资源是非*
	 */
	public void test_ListMFADevices_Allow_Action_NotALL() throws JSONException {
		// 创建policy
		String policyName = "ListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		// 验证请求
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String listMFADeviceString2 = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listMFADeviceString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

	}

	@Test
	/*
	 * 10.allow NotAction=ListMFADevices, NotResource=user/user2 允许非ListMFADevices
	 * 但是资源是非user/user1
	 */
	public void test_ListMFADevices_Allow_NotAction_NotUser1() throws JSONException {
		// 创建policy
		String policyName = "ListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_2"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// user1、user2 list都不允许
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, user1Name,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user1Name + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String listMFADeviceString2 = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, userName,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listMFADeviceString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		// listVirtualMFADevices,允许
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 200);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				policyName1, policyString1, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey, null);

	}

	@Test
	/*
	 * 11.allow NotAction=ListMFADevices, NotResource=user/* 允许非ListMFADevices
	 * 但是资源是非user/*
	 */
	public void test_ListMFADevices_Allow_NotAction_NotUserALL() throws JSONException {
		// 创建policy
		String policyName = "ListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// user1、user2 list都不允许
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, user1Name,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user1Name + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String listMFADeviceString2 = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, userName,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listMFADeviceString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeleteVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				policyName1, policyString1, accountId);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user2accessKey, user2secretKey, "lala_18",
				tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey, null);
	}

	@Test
	/*
	 * 12.allow NotAction=ListMFADevices, NotResource=* 允许非ListMFADevices 但是资源是非*
	 */
	public void test_ListMFADevices_Allow_NotAction_NotALL() throws JSONException {
		// 创建policy
		String policyName = "EnableMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListMFADevices"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// user1、user2 list都不允许
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, user1Name,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user1Name + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String listMFADeviceString2 = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, userName,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listMFADeviceString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21",
				tags, policyName, policyString, accountId, "group1", "mfa3");
	}

	@Test
	/*
	 * 13.Deny Action=ListMFADevices, resource=user/user1 显示拒绝
	 */
	public void test_ListMFADevices_Deny_Action_user1() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "ListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String policyName2 = "AllowListMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限list，但有权限enable, deactivate
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);

	}

	@Test
	/*
	 * 14.Deny Action=ListMFADevices, resource=user/*
	 */
	public void test_ListMFADevices_Deny_Action_userall() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String policyName2 = "AllowListMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限list，但有权限enable, deactivate
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);

	}

	@Test
	/*
	 * 15.Deny Action=ListMFADevices, resource=*
	 */
	public void test_ListMFADevices_Deny_Action_all() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String policyName2 = "AllowListMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限list，但有权限create, delete, enable, deactivate
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

	}

	@Test
	/*
	 * b.Deny Action=ListMFADevices, resource=mfa/* 资源不匹配，deny失败
	 */
	public void test_ListMFADevices_Deny_Action_ReourceNotMatch() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝资源不匹配未生效
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String policyName2 = "AllowListMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝未生效，有显示允许，user1可以list,可以create,delete(action不匹配)
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
	}

	@Test
	/*
	 * 16.Deny Action=ListMFADevices, NotResource=user/user1
	 * 资源非user1,显示拒绝user1失效，显示拒绝user2生效
	 */
	public void test_ListMFADevices_Deny_Action_NotResouce_user1() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 一个隐式拒绝，一个显式拒绝
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		String policyName2 = "AllowListMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝user1失效
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);

		// 显示拒绝user2生效
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 403);

	}

	@Test
	/*
	 * 17.Deny Action=ListMFADevices, NotResource=user/*
	 */
	public void test_ListMFADevices_Deny_Action_NotResouce_userAll() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		String policyName2 = "AllowListMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝user1失效
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);

		// 显示拒绝user2失效
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 200);
	}

	@Test
	/*
	 * 18.Deny Action=ListMFADevices, NotResource=*
	 */
	public void test_ListMFADevices_Deny_Action_NotResouce_All() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		String policyName2 = "AllowListMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝user1失效
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);

		// 显示拒绝user2失效
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 200);
	}

	@Test
	/*
	 * 19.Deny NotAction=ListMFADevices, Resource=user/user1
	 */
	public void test_ListMFADevices_Deny_NotAction_Resource_user1() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		String policyName2 = "AllowListMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除ListMFADevices以外的方法
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

		// 显示拒绝user2失效
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 403);

	}

	@Test
	/*
	 * 20.Deny NotAction=ListMFADevices, Resource=user/*
	 */
	public void test_ListMFADevices_Deny_NotAction_Resource_userAll() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		String policyName2 = "AllowListMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除ListMFADevices以外的方法
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		// IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1,
		// user1secretKey1, accountId, MFADeviceName, 200);

		// 显示拒绝除ListMFADevices以外的方法
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 200);
	}

	@Test
	/*
	 * 21.Deny NotAction=ListMFADevices, Resource=*
	 */
	public void test_ListMFADevices_Deny_NotAction_Resource_All() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListMFADevices"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		String policyName2 = "AllowListMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除ListMFADevices以外的方法
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

		// 显示拒绝除ListMFADevices以外的方法
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 403);
	}

	@Test
	/*
	 * 22.Deny NotAction=ListMFADevices, NotResource=user/user1
	 */
	public void test_ListMFADevices_Deny_NotAction_NotResource_user1() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 一个隐式拒绝，一个显式拒绝
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		String policyName2 = "AllowListMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// user1的操作
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

		// user2的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.EnableMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeactivateMFADevice(accessKey, secretKey, user2Name, accountId, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 403);

	}

	@Test
	/*
	 * 23.Deny NotAction=ListMFADevices, NotResource=user/*
	 */
	public void test_ListMFADevices_Deny_NotAction_NotResource_userAll() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		String policyName2 = "AllowListMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// user1的操作
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

		// user2的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 403);

	}

	@Test
	/*
	 * 24.Deny NotAction=ListMFADevices, NotResource=*
	 */
	public void test_ListMFADevices_Deny_NotAction_NotResource_All() throws JSONException {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListMFADevices"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝
		String listMFADeviceString = IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listMFADeviceString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String enableMFADevice2String = IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(enableMFADevice2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		String policyName2 = "AllowListMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// user1的操作
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> root = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, root.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(root.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		// IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1,
		// user1secretKey1, accountId, MFADeviceName, 200);

		// user2的操作
		IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 200);
		IAMInterfaceTestUtils.ListMFADevices(user2accessKey, user2secretKey, user2Name, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user2accessKey, user2secretKey, user2Name, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user2accessKey, user2secretKey, accountId, MFADeviceName, 200);

	}

	@Test
	/*
	 * c.在IP范围的允许访问
	 */
	public void test_ListMFADevices_Condition_sourceIP() {
		String userName = user1Name;
		String policyName = "allowspecialIP";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.168.1.1/24")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 在IP范围
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		String body = "Action=ListMFADevices&Version=2010-05-08&UserName=" + userName;
		List<Pair<String, String>> params = new ArrayList<Pair<String, String>>();
		Pair<String, String> param1 = new Pair<String, String>();
		param1.first("X-Forwarded-For");
		param1.second("192.168.1.101");
		params.add(param1);

		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1, params);
		assertEquals(200, result.first().intValue());

		// 不在IP范围
		List<Pair<String, String>> params2 = new ArrayList<Pair<String, String>>();
		Pair<String, String> param2 = new Pair<String, String>();
		param2.first("X-Forwarded-For");
		param2.second("192.168.2.101");
		params2.add(param2);

		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,
				params2);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * d.符合username匹配允许访问
	 */
	public void test_ListMFADevices_Condition_username() {
		String userName = "test_1";
		String policyName = "allowUsername";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// username 符合条件
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		String body = "Action=ListMFADevices&Version=2010-05-08&UserName=" + userName;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		// username 不符合条件
		serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=ListMFADevices&Version=2010-05-08&UserName=" + user3Name;
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(body, user3accessKey, user3secretKey);
		assertEquals(403, result3.first().intValue());
	}

	@Test
	/*
	 * e.符合实际条件允许访问
	 */
	public void test_ListMFADevices_Condition_CurrentTime() {
		String userName = "test_1";
		String policyName = "allowDateGreate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2019-01-01T00:00:00Z")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 时间符合条件
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		String body = "Action=ListMFADevices&Version=2010-05-08&UserName=" + userName;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2050-01-01T00:00:00Z")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 时间不符合条件
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * f.设置不允许ssl访问
	 */
	public void test_ListMFADevices_Condition_SecureTransport() {
		String userName = "test_1";
		String policyName = "DenySSL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 允许ssl访问
		String serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		String body = "Action=ListMFADevices&Version=2010-05-08&UserName=" + userName;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("false")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 不允许ssl访问
		serialNumber = "arn:ctyun:iam::" + accountId + ":mfa/" + MFADeviceName;
		body = "Action=ListMFADevices&Version=2010-05-08&UserName=" + userName;
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());

	}

	// ==========================ListVirtualMFADevices=============================================
	/*
	 * 1.allow Action=ListVirtualMFADevices, resource=mfa/mfaDevice1
	 * ListVirtualMFADevices操作的资源都是mfa/*,该测试用例没有意义
	 */

	@Test
	/*
	 * 2.allow Action=ListVirtualMFADevices, resource=mfa/* 可以ListVirtualMFADevices
	 */
	public void test_ListVirtualMFADevices_Allow_Action_all() throws JSONException {
		// 创建policy
		String policyName = "ListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String MFADeviceName = "testVirtualMFADevice01";
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);

		String user2xmlString = IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));

	}

	@Test
	/*
	 * 3.allow Action=ListVirtualMFADevices, resource=* 可以创建所有mfaDevice
	 */
	public void test_ListVirtualMFADevices_Allow_Action_all2() throws JSONException {
		// 创建policy
		String policyName = "ListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String MFADeviceName = "testVirtualMFADevice01";
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);

		String user2xmlString = IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}

	@Test
	/*
	 * a.allow Action=ListVirtualMFADevices, resource=user/*
	 * 资源和请求的action不匹配，policy不生效
	 */
	public void test_ListVirtualMFADevices_Allow_Action_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyName = "ListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		// 验证请求
		String MFADeviceName = "testVirtualMFADevice01";
		IAMInterfaceTestUtils.CreateVirtualMFADevice(accessKey, secretKey, MFADeviceName, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String user2xmlString = IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
	}

	/*
	 * 4.allow NotAction=ListVirtualMFADevices, resource=mfa/mfaDevice1
	 * ListVirtualMFADevices操作的资源都是mfa/*,该测试用例没有意义
	 */

	@Test
	/*
	 * 5.allow NotAction=ListVirtualMFADevices, resource=mfa/*
	 * 资源resource只能匹配除了ListVirtualMFADevices的其他VirtualMFADevice相关操作
	 */
	public void test_ListVirtualMFADevices_Allow_NotAction_mfaDeviceall() throws JSONException {
		//
		String policyName = "ListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证user1不能list
		String user1xmlString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));

		// 验证 除了 ListVirtualMFADevices其他跟mfa/*相关的方法都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("ListVirtualMFADevices");
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, accountId, MFADeviceName);

		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyName, policyString, accountId);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"test_11", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 6.allow NotAction=ListVirtualMFADevices, resource=*
	 * 可匹配除了ListVirtualMFADevices的所有其他操作
	 */
	public void test_ListVirtualMFADevices_Allow_NotAction_all() throws JSONException {
		// 创建策略
		String userName = "test_1";
		String policyName = "ListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给用户添加policy
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证user1不能list
		String user1xmlString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));

		// 验证 除了 CreateVirtualMFADevice所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("ListVirtualMFADevices");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "CreateVirtualMFADevicePolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "group1", "mfa2");
	}

	/*
	 * 7.allow Action=ListVirtualMFADevices, NotResource=mfaDevice/mfaDevice1
	 * ListVirtualMFADevices操作的资源都是mfa/*,该测试用例没有意义
	 */

	@Test
	/*
	 * 8.allow Action=ListVirtualMFADevices, NotResource=mfa/*
	 * 允许ListVirtualMFADevices 但是资源是非mfa/*
	 */
	public void test_ListVirtualMFADevices_Allow_Action_NotmfaDeviceALL() throws JSONException {
		// 创建policy
		String policyName = "ListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		String user1xmlString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String user2xmlString = IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
	}

	@Test
	/*
	 * 9.allow Action=ListVirtualMFADevices, NotResource:* 允许ListVirtualMFADevices
	 * 但是资源是非*
	 */
	public void test_ListVirtualMFADevices_Allow_Action_NotALL() throws JSONException {
		// 创建policy
		String policyName = "ListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证请求
		String user1xmlString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String user2xmlString = IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error2.get("Message"));
		assertEquals("/", error2.get("Resource"));
	}

	/*
	 * 10.allow NotAction=ListVirtualMFADevices, NotResource=mfaDevice/mfaDevice1
	 * ListVirtualMFADevices操作的资源都是mfa/*,该测试用例没有意义
	 */

	@Test
	/*
	 * 11.allow NotAction=ListVirtualMFADevices, NotResource=mfa/*
	 * 允许非ListVirtualMFADevices 但是资源是非mfa/*
	 */
	public void test_ListVirtualMFADevices_Allow_NotAction_NotmfaALL() throws JSONException {
		// 创建policy
		String policyName = "ListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListVirtualMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证user1、user2都不能list
		String user1xmlString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String user2xmlString = IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		// 验证资源是mfa/*的都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user2accessKey, user2secretKey, accountId,
				MFADeviceName);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateVirtualMFADevice"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				policyName1, policyString1, accountId);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user2accessKey, user2secretKey,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user2accessKey, user2secretKey, null);
	}

	@Test
	/*
	 * 12.allow NotAction=ListVirtualMFADevices, NotResource=*
	 * 允许非ListVirtualMFADevices 但是资源是非*
	 */
	public void test_ListVirtualMFADevices_Allow_NotAction_NotALL() throws JSONException {
		// 创建policy
		String policyName = "CreateMFADevicePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListVirtualMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "test_2";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 验证创建group1 和group2都不允许
		String user1xmlString = IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));
		String user2xmlString = IAMInterfaceTestUtils.ListVirtualMFADevices(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName
				+ " is not authorized to perform: iam:ListVirtualMFADevices on resource: arn:ctyun:iam::3rmoqzn03g6ga:mfa/*.",
				error2.get("Message"));
		assertEquals("/", error2.get("Resource"));

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21",
				tags, policyName, policyString, accountId, "group1", "mfa3");
	}

	/*
	 * 13.Deny Action=CreateVirtualMFADevice, resource=mfa/mfaDevice1
	 * ListVirtualMFADevices操作的资源都是mfa/*,该测试用例没有意义
	 */

	@Test
	/*
	 * 14.Deny Action=ListVirtualMFADevices, resource=mfa/*
	 */
	public void test_ListVirtualMFADevices_Deny_Action_mfaall() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);

		String policyName2 = "AllowListVirtualMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限list，但有权限create和delete
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);
	}

	@Test
	/*
	 * 15.Deny Action=ListVirtualMFADevices, resource=*
	 */
	public void test_ListVirtualMFADevices_Deny_Action_all() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);

		String policyName2 = "AllowListVirtualMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限list，但有权限create和delete
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);
	}

	@Test
	/*
	 * b.Deny Action=ListVirtualMFADevices, resource=user/* 资源不匹配，deny失败
	 */
	public void test_ListVirtualMFADevices_Deny_Action_ReourceNotMatch() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 显示拒绝资源不匹配未生效
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);

		String policyName2 = "AllowListVirtualMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝未生效，有显示允许，user1可以create，delete和list
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);
	}

	/*
	 * 16.Deny Action=ListVirtualMFADevices, NotResource=mfa/mfaDevice1
	 * ListVirtualMFADevices操作的资源都是mfa/*,该测试用例没有意义
	 */

	@Test
	/*
	 * 17.Deny Action=ListVirtualMFADevices, NotResource=mfa/*
	 */
	public void test_ListVirtualMFADevices_Deny_Action_NotResouce_mfaAll() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);

		String policyName2 = "AllowListVirtualMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝mfaDevice1失效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// 显示拒绝mfaDevice2失效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	@Test
	/*
	 * 18.Deny Action=ListVirtualMFADevices, NotResource=*
	 */
	public void test_ListVirtualMFADevices_Deny_Action_NotResouce_All() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);

		String policyName2 = "AllowListVirtualMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝mfaDevice1失效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

		// 显示拒绝mfaDevice2失效
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName2, 200);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName2, 200);

	}

	/*
	 * 19.Deny NotAction=ListVirtualMFADevices, Resource=mfa/mfaDevice1
	 * ListVirtualMFADevices操作的资源都是mfa/*,该测试用例没有意义
	 */

	@Test
	/*
	 * 20.Deny NotAction=ListVirtualMFADevices, Resource=mfa/*
	 */
	public void test_ListVirtualMFADevices_Deny_NotAction_Resource_mfaAll() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);

		String policyName2 = "AllowListVirtualMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝除list以外的方法
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, user1.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(user1.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.CreateVirtualMFADevice(user1accessKey1, user1secretKey1, MFADeviceName, 403);
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);

	}

	@Test
	/*
	 * 21.Deny NotAction=ListVirtualMFADevices, Resource=*
	 */
	public void test_ListVirtualMFADevices_Deny_NotAction_Resource_All() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);

		String policyName2 = "AllowListVirtualMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝除list以外的方法
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, user1.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(user1.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 403);

	}

	/*
	 * 22.Deny NotAction=ListVirtualMFADevices, NotResource=mfa/mfaDevice1
	 * ListVirtualMFADevices操作的资源都是mfa/*,该测试用例没有意义
	 */

	@Test
	/*
	 * 23.Deny NotAction=ListVirtualMFADevices, NotResource=mfa/*
	 */
	public void test_ListVirtualMFADevices_Deny_NotAction_NotResource_mfaAll() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListVirtualMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);

		String policyName2 = "AllowListVirtualMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 资源是非mfa,操作是非list的拒绝
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(user1.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 403);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 403);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				403);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

	}

	@Test
	/*
	 * 24.Deny NotAction=ListVirtualMFADevices, NotResource=*
	 */
	public void test_ListVirtualMFADevices_Deny_NotAction_NotResource_All() {
		String userName = "test_1";
		// 创建policy
		String policyName = "DenyListVirtualMFADevicesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListVirtualMFADevices"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 403);

		String policyName2 = "AllowListVirtualMFADevicesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices",
						"iam:ListMFADevices", "iam:EnableMFADevice", "iam:DeactivateMFADevice"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// mfaDevice1的操作除了create以外都拒绝
		String body = "Action=CreateVirtualMFADevice&Version=2010-05-08&VirtualMFADeviceName=" + MFADeviceName;
		Pair<Integer, String> user1 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, user1.first().intValue());
		Pair<String, String> devicePair = AssertcreateVirtualMFADevice(user1.second(),
				"arn:ctyun:iam::3rmoqzn03g6ga:mfa/" + MFADeviceName);
		Pair<String, String> authenticationCode = CreateIdentifyingCode(devicePair.second());
		String authenticationCode11 = authenticationCode.first();
		String authenticationCode12 = authenticationCode.second();
		IAMInterfaceTestUtils.ListVirtualMFADevices(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.ListMFADevices(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.EnableMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				authenticationCode11, authenticationCode12, 200);
		IAMInterfaceTestUtils.DeactivateMFADevice(user1accessKey1, user1secretKey1, userName, accountId, MFADeviceName,
				200);
		IAMInterfaceTestUtils.DeleteVirtualMFADevice(user1accessKey1, user1secretKey1, accountId, MFADeviceName, 200);

	}

	@Test
	/*
	 * c.在IP范围的允许访问
	 */
	public void test_ListVirtualMFADevices_Condition_sourceIP() {
		String userName = user1Name;
		String policyName = "allowspecialIP";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.168.1.1/24")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 在IP范围
		String body = "Action=ListVirtualMFADevices&Version=2010-05-08";
		List<Pair<String, String>> params = new ArrayList<Pair<String, String>>();
		Pair<String, String> param1 = new Pair<String, String>();
		param1.first("X-Forwarded-For");
		param1.second("192.168.1.101");
		params.add(param1);

		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1, params);
		assertEquals(200, result.first().intValue());

		// 不在IP范围
		List<Pair<String, String>> params2 = new ArrayList<Pair<String, String>>();
		Pair<String, String> param2 = new Pair<String, String>();
		param2.first("X-Forwarded-For");
		param2.second("192.168.2.101");
		params2.add(param2);

		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest2(body, user1accessKey1, user1secretKey1,
				params2);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * d.符合username匹配允许访问
	 */
	public void test_ListVirtualMFADevices_Condition_username() {
		String userName = "test_1";
		String policyName = "allowUsername";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// username 符合条件
		String body = "Action=ListVirtualMFADevices&Version=2010-05-08";
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		// username 不符合条件
		body = "Action=ListVirtualMFADevices&Version=2010-05-08";
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(body, user3accessKey, user3secretKey);
		assertEquals(403, result3.first().intValue());
	}

	@Test
	/*
	 * e.符合实际条件允许访问
	 */
	public void test_ListVirtualMFADevices_Condition_CurrentTime() {
		String userName = "test_1";
		String policyName = "allowDateGreate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2019-01-01T00:00:00Z")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 时间符合条件
		String body = "Action=ListVirtualMFADevices&Version=2010-05-08";
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2050-01-01T00:00:00Z")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 时间不符合条件
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * f.设置不允许ssl访问
	 */
	public void test_ListVirtualMFADevices_Condition_SecureTransport() {
		String userName = "test_1";
		String policyName = "DenySSL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String MFADeviceName = "testMFADevice01";
		String MFADeviceName2 = "testMFADevice02";

		// 允许ssl访问
		String body = "Action=ListVirtualMFADevices&Version=2010-05-08";
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("false")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListVirtualMFADevices"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 不允许ssl访问
		body = "Action=ListVirtualMFADevices&Version=2010-05-08";
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());

	}

	public static String AssertCreateUserResult(String xml, String userName, List<Pair<String, String>> tags) {
		try {
			StringReader sr = new StringReader(xml);
			InputSource is = new InputSource(sr);
			Document doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();

			Element createUserResultElement = root.getChild("CreateUserResult");
			Element UserElement = createUserResultElement.getChild("User");

			String userId = UserElement.getChild("UserId").getValue();
			System.out.println(userId);
			assertEquals(userName, UserElement.getChild("UserName").getValue());

			if (tags != null && tags.size() > 0) {
				@SuppressWarnings("unchecked")
				List<Element> memberElements = UserElement.getChild("Tags").getChildren("member");
				for (int i = 0; i < tags.size(); i++) {
					Pair<String, String> pair = tags.get(i);
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
		// 补全IdentifyingCode前面缺少的零
		String firstCode = addZeroForNum(codePair.first(), 6);
		String secondCode = addZeroForNum(codePair.second(), 6);
		codePair.first(firstCode);
		codePair.second(secondCode);
		return codePair;
	}

	private static int generateCode(byte[] key, long t) {
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

	public Pair<String, String> AssertcreateVirtualMFADevice(String xml, String serialNumber) {
		try {
			StringReader sr = new StringReader(xml);
			InputSource is = new InputSource(sr);
			Document doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();

			Element resultElement = root.getChild("CreateVirtualMFADeviceResult");
			Element virtualMFADevice = resultElement.getChild("VirtualMFADevice");
			String SerialNumber = virtualMFADevice.getChild("SerialNumber").getValue();
			String Base32StringSeed = virtualMFADevice.getChild("Base32StringSeed").getValue();
			String QRCodePNG = virtualMFADevice.getChild("QRCodePNG").getValue();
			System.out.println("QRCodePNG=" + QRCodePNG);
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

	public static String addZeroForNum(String str, int strLength) {
		int strLen = str.length();
		StringBuffer sb = null;
		while (strLen < strLength) {
			sb = new StringBuffer();
			sb.append("0").append(str); // 不足6位左补0
			str = sb.toString();
			strLen = str.length();
		}
		return str;
	}
	
	
	public void AssertAccessDenyString(String xml, String methodString, String userName, String resource) {
        try {
            JSONObject error = IAMTestUtils.ParseErrorToJson(xml);
            assertEquals("AccessDenied", error.get("Code"));
            assertEquals(
                    "User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + userName + " is not authorized to perform: iam:"
                            + methodString + " on resource: arn:ctyun:iam::3rmoqzn03g6ga:" + resource + ".",
                    error.get("Message"));
            //assertEquals("/", error.get("Resource"));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
