package cn.ctyun.oos.iam.test.iamaccesscontrol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.client.HBaseAdmin;
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

import cn.ctyun.common.Consts;
import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.hbase.HBaseUserToTag;
import cn.ctyun.oos.hbase.HBaseVSNTag;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.metadata.UserToTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta.VSNTagType;
import common.tuple.Pair;

public class PolicyActionAccessTest {
	public static final String OOS_IAM_DOMAIN = "https://oos-loc6-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName = "loc6";

	private static String ownerName = "root_user@test.com";
	public static final String accessKey = "userak";
	public static final String secretKey = "usersk";

	public static final String user1Name = "test_1";
	public static final String user2Name = "test_2";
	public static final String user3Name = "user_3";
	public static final String groupName = "testGroup_1";
	public static final String groupName2 = "testGroup_2";
	public static final String testGroup1 = "testGroup1";
	public static final String testGroup2 = "testGroup2";
	public static final String user1accessKey1 = "abcdefghijklmnop";
	public static final String user1secretKey1 = "cccccccccccccccc";
	public static final String user1accessKey2 = "1234567890123456";
	public static final String user1secretKey2 = "user1secretKey2lllll";
	public static final String user2accessKey = "qrstuvwxyz0000000";
	public static final String user2secretKey = "bbbbbbbbbbbbbbbbbb";
	public static final String user3accessKey = "abcdefgh12345678";
	public static final String user3secretKey = "3333333333333333";

	public static final String testUser1 = "test_User_01";
	public static final String testUser2 = "test_User_02";

	public static final String policyName = "PolicyActionPolicy";
	public static final String testPolicy1 = "testPolicy1";
	public static final String testPolicy2 = "testPolicy2";

	public static String accountId = "3rmoqzn03g6ga";
	public static String mygroupName = "mygroup";

	public static OwnerMeta owner = new OwnerMeta(ownerName);
	public static MetaClient metaClient = MetaClient.getGlobalClient();
	static Configuration globalConf = GlobalHHZConfig.getConfig();

	@Test
	public void test() {
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name,
				"condition_UserAgentStringEquals_policy", 200);
//		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, "condition_UserAgentStringEquals_policy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "condition_UserAgentStringEquals_policy",
				200);

	}

//	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		IAMTestUtils.TrancateTable("oos-aksk-wtz2");
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
		User user1 = new User();
		user1.accountId = accountId;
		user1.userName = UserName1;
		user1.userId = "test1abc";
		user1.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user1);
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
		aksk1.accessKey = user1accessKey1;
		aksk1.setSecretKey(user1secretKey1);
		metaClient.akskInsert(aksk1);
		user1.accessKeys = new ArrayList<>();
		user1.accessKeys.add(aksk1.accessKey);

		aksk1.accessKey = user1accessKey2;
		aksk1.setSecretKey(user1secretKey2);
		metaClient.akskInsert(aksk1);
		user1.accessKeys.add(aksk1.accessKey);
		HBaseUtils.put(user1);

		String UserName2 = user2Name;
		User user2 = new User();
		user2.accountId = accountId;
		user2.userName = UserName2;
		user2.userId = "Test1Abc";
		user2.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user2);
			assertTrue(success);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		AkSkMeta aksk2 = new AkSkMeta(owner.getId());
		aksk2.isRoot = 0;
		aksk2.userId = user2.userId;
		aksk2.userName = UserName2;
		aksk2.accessKey = user2accessKey;
		aksk2.setSecretKey(user2secretKey);
		metaClient.akskInsert(aksk2);
		user2.accessKeys = new ArrayList<>();
		user2.userName = UserName2;
		user2.accessKeys.add(aksk2.accessKey);
		HBaseUtils.put(user2);

		String UserName3 = user3Name;
		User user3 = new User();
		user3.accountId = accountId;
		user3.userName = UserName3;
		user3.userId = "abc1";
		user3.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user3);
			assertTrue(success);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		AkSkMeta aksk3 = new AkSkMeta(owner.getId());
		aksk3.isRoot = 0;
		aksk3.userId = user3.userId;
		aksk3.userName = UserName3;
		aksk3.accessKey = user3accessKey;
		aksk3.setSecretKey(user3secretKey);
		metaClient.akskInsert(aksk3);

		user3.accessKeys = new ArrayList<>();
		user3.userName = UserName3;
		user3.accessKeys.add(aksk3.accessKey);
		HBaseUtils.put(user3);

		HBaseAdmin globalHbaseAdmin = new HBaseAdmin(globalConf);

		HBaseUserToTag.dropTable(GlobalHHZConfig.getConfig());
		HBaseUserToTag.createTable(globalHbaseAdmin);
		HBaseVSNTag.dropTable(GlobalHHZConfig.getConfig());
		HBaseVSNTag.createTable(globalHbaseAdmin);
		Thread.sleep(1000);

		VSNTagMeta dataTag1;
		VSNTagMeta metaTag1;

		dataTag1 = new VSNTagMeta("tag1", Arrays.asList(new String[] { "wtzRegion", "huabei" }), VSNTagType.DATA);
		metaClient.vsnTagInsert(dataTag1);
		metaTag1 = new VSNTagMeta("mtag1", Arrays.asList(new String[] { "wtzRegion" }), VSNTagType.META);
		metaClient.vsnTagInsert(metaTag1);

		UserToTagMeta user2Tag1 = new UserToTagMeta(owner.getId(),
				Arrays.asList(new String[] { dataTag1.getTagName() }), VSNTagType.DATA);
		metaClient.userToTagInsert(user2Tag1);
		UserToTagMeta user2Tag2 = new UserToTagMeta(owner.getId(),
				Arrays.asList(new String[] { metaTag1.getTagName() }), VSNTagType.META);
		metaClient.userToTagInsert(user2Tag2);

	}

	// createPolicy
	@Test
	/*
	 * Allow Action=CreatePolicy Resource=policy/testPolicy1
	 */
	public void test_CreatePolicy_Allow_Action_Resource_testPolicy1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);

		String userxmlString1 = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2,
				policyString, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		String userxmlString2 = IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy1,
				policyString, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=CreatePolicy Resource=policy/*
	 */
	public void test_CreatePolicy_Allow_Action_Resource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);

		String userxmlString2 = IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy1,
				policyString, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=CreatePolicy Resource=*
	 */
	public void test_CreatePolicy_Allow_Action_Resource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);

		String userxmlString2 = IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy1,
				policyString, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=CreatePolicy Resource=user/*
	 */
	public void test_CreatePolicy_Allow_Action_Resource_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String userxmlString = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1,
				policyString, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2,
				policyString, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		String userxmlString2 = IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy1,
				policyString, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow NotAction=CreatePolicy Resource=policy/testPolicy1
	 */
	public void test_CreatePolicy_Allow_NotAction_Resource_testPolicy1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// 创建policy1和policy2都不允许
		String userxmlString = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1,
				policyString, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2,
				policyString, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		// 验证除了createPolicy，其他跟policy相关的操作都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("CreatePolicy");
		IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, testPolicy1, policyString, accountId);

		// 和资源不匹配的testPolicy2不允許
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				testPolicy2, policyString, accountId);

		// 验证 跟MFA资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newGroup", testUser1, accountId, "newPolicy", policyString);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"lala_1", tags, policyName, policyString, accountId);
		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * Allow NotAction=CreatePolicy Resource=policy/*
	 */
	public void test_CreatePolicy_Allow_NotAction_Resource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// 创建policy1和policy2都不允许
		String userxmlString = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1,
				policyString, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2,
				policyString, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		// 验证除了createPolicy，其他跟policy相关的操作都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("CreatePolicy");
		IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, testPolicy1, policyString, accountId);

		IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, testPolicy2, policyString, accountId);

		// 验证 跟MFA资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newGroup", testUser1, accountId, "newPolicy", policyString);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"lala_1", tags, policyName, policyString, accountId);
		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * Allow NotAction=CreatePolicy Resource=*
	 */
	public void test_CreatePolicy_Allow_NotAction_Resource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreatePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// 创建policy1和policy2都不允许
		String userxmlString = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1,
				policyString, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2,
				policyString, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		// 验证 除了 createPolicy所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("CreatePolicy");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "CreateGroupPolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateGroup"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "newGroup", "mfa2");
	}

	@Test
	/*
	 * Allow Action=CreatePolicy NotResource=policy/testPolicy1
	 */
	public void test_CreatePolicy_Allow_Action_NotResource_testPolicy1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String userxmlString = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1,
				policyString, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
	}

	@Test
	/*
	 * Allow Action=CreatePolicy NotResource=policy/*
	 */
	public void test_CreatePolicy_Allow_Action_NotResource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String userxmlString = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1,
				policyString, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2,
				policyString, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=CreatePolicy NotResource=*
	 */
	public void test_CreatePolicy_Allow_Action_NotResource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String userxmlString = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1,
				policyString, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2,
				policyString, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));
	}

	@Test
	/*
	 * Allow NotAction=CreatePolicy NotResource=policy/testPolicy1
	 */
	public void test_CreatePolicy_Allow_NotAction_NotResource_testPolicy1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreatePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// 验证创建group1和group2都不允许
		String userxmlString = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1,
				policyString, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2,
				policyString, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		// 资源为testPolicy1的是都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey1, user1secretKey1,
				testPolicy1, policyString, accountId);

		// 验证 跟MFA资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newGroup", "newUser", accountId, "newPolicy", policyString);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * Allow NotAction=CreatePolicy NotResource=policy/*
	 */
	public void test_CreatePolicy_Allow_NotAction_NotResource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreatePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// 验证创建group1和group2都不允许
		String userxmlString = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1,
				policyString, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2,
				policyString, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey1, user1secretKey1,
				testPolicy2, policyString, accountId);

		// 验证 跟MFA资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newGroup", "newUser", accountId, "newPolicy", policyString);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * Allow NotAction=CreatePolicy NotResource=*
	 */
	public void test_CreatePolicy_Allow_NotAction_NotResource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreatePolicy"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// 验证创建group1和group2都不允许
		String userxmlString = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1,
				policyString, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2,
				policyString, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:CreatePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21",
				tags, policyName, policyString, accountId, "newGroup", "mfa3");
	}

	@Test
	/*
	 * Deny Action=CreatePolicy Resource=policy/testPolicy1
	 */
	public void test_CreatePolicy_Deny_Action_Resource_testPolicy1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 显式拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

	}

	@Test
	/*
	 * Deny Action=CreatePolicy Resource=policy/*
	 */
	public void test_CreatePolicy_Deny_Action_Resource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 显式拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

	}

	@Test
	/*
	 * Deny Action=CreatePolicy Resource=*
	 */
	public void test_CreatePolicy_Deny_Action_Resource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 显式拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

	}

	@Test
	/*
	 * Deny Action=CreatePolicy Resource=user/*
	 */
	public void test_CreatePolicy_Deny_Action_Resource_resourceNotMatch() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

	}

	@Test
	/*
	 * Deny Action=CreatePolicy NotResource=policy/testPolicy1
	 */
	public void test_CreatePolicy_Deny_Action_NotResource_testPolicy1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny Action=CreatePolicy NotResource=policy/*
	 */
	public void test_CreatePolicy_Deny_Action_NotResource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny Action=CreatePolicy NotResource=*
	 */
	public void test_CreatePolicy_Deny_Action_NotResource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny NotAction=CreatePolicy Resource=policy/testPolicy1
	 */
	public void test_CreatePolicy_Deny_NotAction_Resource_testPolicy1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny NotAction=CreatePolicy Resource=policy/*
	 */
	public void test_CreatePolicy_Deny_NotAction_Resource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

	}

	@Test
	/*
	 * Deny NotAction=CreatePolicy Resource=*
	 */
	public void test_CreatePolicy_Deny_NotAction_Resource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreatePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

	}

	@Test
	/*
	 * Deny NotAction=CreatePolicy NotResource=policy/testPolicy1
	 */
	public void test_CreatePolicy_Deny_NotAction_NotResource_testPolicy1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreatePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

	}

	@Test
	/*
	 * Deny NotAction=CreatePolicy NotResource=policy/*
	 */
	public void test_CreatePolicy_Deny_NotAction_NotResource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreatePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny NotAction=CreatePolicy NotResource=*
	 */
	public void test_CreatePolicy_Deny_NotAction_NotResource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:CreatePolicy"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	public void test_createPolicy_condition_StringEquals_allow() throws JSONException {
		// 创建policy
		String policy = "condition_StringEquals_policy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals", "ctyun:username", Arrays.asList("ak_test_1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy, policyString, 200);

		// 给用户添加policy，并验证
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy2, policyString, 403);

		// 用户解绑策略，并删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
	}

	@Test
	public void test_createPolicy_condition_UserAgentStringEquals_allow() throws JSONException {
		// 创建policy
		String policy = "condition_UserAgentStringEquals_policy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals", "ctyun:UserAgent", Arrays.asList("Java/1.7.0")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy, policyString, 200);

		// 给用户添加policy，并验证
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);// 实际为：

		// 用户解绑策略，并删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy, 200);
//		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
	}

	@Test
	public void test_createPolicy_condition_StringEquals_deny() throws JSONException {
		// 创建policy
		String policy = "condition_StringEquals_policy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals", "ctyun:username", Arrays.asList("ak_test_1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy, policyString, 200);

		String policy2 = "condition_StringEquals_policy_allow";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy2, policyString2, 200);

		// 给用户添加policy，并验证
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy2, 200);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy2, policyString, 200);

		// 用户解绑策略，并删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);
	}

	@Test
	public void test_createPolicy_condition_StringNotEquals_allow() throws JSONException {
		// 创建policy
		String policy = "condition_StringNotEquals_policy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEquals", "ctyun:username", Arrays.asList("ak_test_1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy, policyString, 200);

		// 给用户添加policy,并验证
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy2, policyString, 200);

		// 用户解绑策略，并删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);
	}

	@Test
	public void test_createPolicy_condition_StringNotEquals_deny() throws JSONException {
		// 创建policy
		String policy = "condition_StringNotEquals_policy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEquals", "ctyun:username", Arrays.asList("ak_test_1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy, policyString, 200);

		String policy2 = "policy_allow";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy2, policyString2, 200);

		// 给用户添加policy，并验证
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy2, 200);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy2, policyString, 403);

		// 用户解绑策略，并删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
	}

	@Test
	public void test_createPolicy_condition_StringEqualsIgnoreCase_allow() throws JSONException {
		String policy = "condition_StringEqualsIgnoreCase_policy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(
				IAMTestUtils.CreateCondition("StringEqualsIgnoreCase", "ctyun:username", Arrays.asList("Ak_test_1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy, policyString, 200);

		// 给用户添加policy,并验证
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy2, policyString, 403);

		// 用户解绑策略，并删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
	}

	@Test
	public void test_createPolicy_condition_StringEqualsIgnoreCase_deny() throws JSONException {
		// 创建policy
		String policy = "condition_StringEqualsIgnoreCase_deny_policy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(
				IAMTestUtils.CreateCondition("StringEqualsIgnoreCase", "ctyun:username", Arrays.asList("Ak_test_1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy, policyString, 200);

		String policy2 = "policy_allow";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy2, policyString2, 200);

		// 给用户添加policy，并验证
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy2, 200);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy2, policyString, 200);

		// 用户解绑策略，并删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);
	}

	@Test
	public void test_createPolicy_condition_StringNotEqualsIgnoreCase_allow() throws JSONException {
		String policy = "condition_StringNotEqualsIgnoreCase_policy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase", "ctyun:username",
				Arrays.asList("Ak_test_1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy, policyString, 200);

		// 给用户添加policy,并验证
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy2, policyString, 200);

		// 用户解绑策略，并删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);
	}

	@Test
	public void test_createPolicy_condition_StringNotEqualsIgnoreCase_deny() throws JSONException {
		// 创建policy
		String policy = "condition_StringNotEqualsIgnoreCase_deny_policy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase", "ctyun:username",
				Arrays.asList("Ak_test_1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy, policyString, 200);

		String policy2 = "policy_allow";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy2, policyString2, 200);

		// 给用户添加policy，并验证
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy2, 200);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy2, policyString, 403);

		// 用户解绑策略，并删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
	}

	@Test
	public void test_createPolicy_condition_StringLike_allow() throws JSONException {
		String policy = "condition_StringLike_policy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("ak_test_*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy, policyString, 200);

		// 给用户添加policy,并验证
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy2, policyString, 200);

		// 用户解绑策略，并删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);
	}

	@Test
	public void test_createPolicy_condition_StringLike_deny() throws JSONException {
		// 创建policy
		String policy = "condition_StringLike_deny_policy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("ak_test_*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy, policyString, 200);

		String policy2 = "policy_allow";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy2, policyString2, 200);

		// 给用户添加policy，并验证
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy2, 200);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy2, policyString, 403);

		// 用户解绑策略，并删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy2, 200);
	}

	@Test
	public void test_createPolicy_condition_StringNotLike_allow() throws JSONException {
		String policy = "condition_StringNotLike_policy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotLike", "ctyun:username", Arrays.asList("ak_test_*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy, policyString, 200);

		// 给用户添加policy,并验证
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policy, 200);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy2, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(user3accessKey, user3secretKey, testPolicy2, policyString, 200);

		// 用户解绑策略，并删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user3Name, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);
	}

	@Test
	public void test_createPolicy_condition_StringNotLike_deny() throws JSONException {
		// 创建policy
		String policy = "condition_StringNotLike_deny_policy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotLike", "ctyun:username", Arrays.asList("ak_test_*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy, policyString, 200);

		String policy2 = "policy_allow";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policy2, policyString2, 200);

		// 给用户添加policy，并验证
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policy2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policy2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policy2, 200);
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(user3accessKey, user3secretKey, testPolicy2, policyString, 403);

		// 用户解绑策略，并删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policy2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);
	}

	// deletePolicy
	@Test
	/*
	 * Allow Action=DeletePolicy Resource=policy/testPolicy1
	 */
	public void test_DeletePolicy_Allow_Action_Resource_testPolicy1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeletePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		String userxmlString1 = IAMInterfaceTestUtils.DeletePolicy(user2accessKey, user2secretKey, accountId,
				testPolicy1, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString2 = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=DeletePolicy Resource=policy/*
	 */
	public void test_DeletePolicy_Allow_Action_Resource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeletePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		String userxmlString1 = IAMInterfaceTestUtils.DeletePolicy(user2accessKey, user2secretKey, accountId,
				testPolicy1, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
	}

	@Test
	/*
	 * Allow Action=DeletePolicy Resource=*
	 */
	public void test_DeletePolicy_Allow_Action_Resource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeletePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		String userxmlString1 = IAMInterfaceTestUtils.DeletePolicy(user2accessKey, user2secretKey, accountId,
				testPolicy1, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
	}

	@Test
	/*
	 * Allow Action=DeletePolicy Resource=user/*
	 */
	public void test_DeletePolicy_Allow_Action_Resource_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeletePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		String userxmlString1 = IAMInterfaceTestUtils.DeletePolicy(user2accessKey, user2secretKey, accountId,
				testPolicy1, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		String userxmlString2 = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy1, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString3 = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(userxmlString3);
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error3.get("Message"));
		assertEquals("", error3.get("Resource"));
	}

	@Test
	/*
	 * Allow NotAction=DeletePolicy Resource=policy/testPolicy1
	 */
	public void test_DeletePolicy_Allow_NotAction_Resource_testPolicy1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeletePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// 删除testPolicy1和删除testPolicy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 验证除了deletePolicy，其他跟policy相关的操作都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("DeletePolicy");
		IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, testPolicy1, policyString, accountId);

		// 和资源不匹配的testPolicy2不允許
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				testPolicy2, policyString, accountId);

		// 验证 跟MFA资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newGroup", testUser1, accountId, "newPolicy", policyString);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"lala_1", tags, policyName, policyString, accountId);
		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * Allow NotAction=DeletePolicy Resource=policy/*
	 */
	public void test_DeletePolicy_Allow_NotAction_Resource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeletePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// 删除testPolicy1和删除testPolicy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 验证除了deletePolicy，其他跟policy相关的操作都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("DeletePolicy");
		IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, testPolicy1, policyString, accountId);

		IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, testPolicy2, policyString, accountId);

		// 验证 跟MFA资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newGroup", testUser1, accountId, "newPolicy", policyString);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"lala_1", tags, policyName, policyString, accountId);
		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * Allow NotAction=DeletePolicy Resource=*
	 */
	public void test_DeletePolicy_Allow_NotAction_Resource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeletePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// 删除testPolicy1和删除testPolicy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 验证 除了 deletePolicy所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("DeletePolicy");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "CreateGroupPolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateGroup"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "newGroup", "mfa2");
	}

	@Test
	/*
	 * Allow Action=DeletePolicy NotResource=policy/testPolicy1
	 */
	public void test_DeletePolicy_Allow_Action_NotResource_testPolicy1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeletePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
	}

	@Test
	/*
	 * Allow Action=DeletePolicy NotResource=policy/*
	 */
	public void test_DeletePolicy_Allow_Action_NotResource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeletePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=DeletePolicy NotResource=*
	 */
	public void test_DeletePolicy_Allow_Action_NotResource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DeletePolicy"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));
	}

	@Test
	/*
	 * Allow NotAction=DeletePolicy NotResource=policy/testPolicy1
	 */
	public void test_DeletePolicy_Allow_NotAction_NotResource_testPolicy1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeletePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// 删除testPolicy1和删除testPolicy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 资源为testPolicy1的是都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey1, user1secretKey1,
				testPolicy1, policyString, accountId);

		// 验证 跟MFA资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newGroup", "newUser", accountId, "newPolicy", policyString);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * Allow NotAction=DeletePolicy NotResource=policy/*
	 */
	public void test_DeletePolicy_Allow_NotAction_NotResource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeletePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// 删除testPolicy1和删除testPolicy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey1, user1secretKey1,
				testPolicy2, policyString, accountId);

		// 验证 跟MFA资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newGroup", "newUser", accountId, "newPolicy", policyString);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * Allow NotAction=DeletePolicy NotResource=*
	 */
	public void test_DeletePolicy_Allow_NotAction_NotResource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DeletePolicy"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// 删除testPolicy1和删除testPolicy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DeletePolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21",
				tags, policyName, policyString, accountId, "newGroup", "mfa3");
	}

	@Test
	/*
	 * Deny Action=DeletePolicy Resource=policy/testPolicy1
	 */
	public void test_DeletePolicy_Deny_Action_Resource_testPolicy1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeletePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 显式拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

	}

	@Test
	/*
	 * Deny Action=DeletePolicy Resource=policy/*
	 */
	public void test_DeletePolicy_Deny_Action_Resource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeletePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 显式拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

	}

	@Test
	/*
	 * Deny Action=DeletePolicy Resource=*
	 */
	public void test_DeletePolicy_Deny_Action_Resource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeletePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 显式拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

	}

	@Test
	/*
	 * Deny Action=DeletePolicy Resource=user/*
	 */
	public void test_DeletePolicy_Deny_Action_Resource_resourceNotMatch() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeletePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

	}

	@Test
	/*
	 * Deny Action=DeletePolicy NotResource=policy/testPolicy1
	 */
	public void test_DeletePolicy_Deny_Action_NotResource_testPolicy1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeletePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

	}

	@Test
	/*
	 * Deny Action=DeletePolicy NotResource=policy/*
	 */
	public void test_DeletePolicy_Deny_Action_NotResource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeletePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny Action=DeletePolicy NotResource=*
	 */
	public void test_DeletePolicy_Deny_Action_NotResource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DeletePolicy"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny NotAction=DeletePolicy Resource=policy/testPolicy1
	 */
	public void test_DeletePolicy_Deny_NotAction_Resource_testPolicy1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeletePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny NotAction=DeletePolicy Resource=policy/*
	 */
	public void test_DeletePolicy_Deny_NotAction_Resource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeletePolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny NotAction=DeletePolicy Resource=*
	 */
	public void test_DeletePolicy_Deny_NotAction_Resource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeletePolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny NotAction=DeletePolicy NotResource=policy/testPolicy1
	 */
	public void test_DeletePolicy_Deny_NotAction_NotResource_testPolicy1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeletePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny NotAction=DeletePolicy NotResource=policy/*
	 */
	public void test_DeletePolicy_Deny_NotAction_NotResource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeletePolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny NotAction=DeletePolicy NotResource=*
	 */
	public void test_DeletePolicy_Deny_NotAction_NotResource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DeletePolicy"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	// getPolicy
	@Test
	/*
	 * Allow Action=GetPolicy Resource=policy/testPolicy1
	 */
	public void test_GetPolicy_Allow_Action_Resource_testPolicy1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		String userxmlString1 = IAMInterfaceTestUtils.GetPolicy(user2accessKey, user2secretKey, accountId, testPolicy1,
				403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString2 = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

	}

	@Test
	/*
	 * Allow Action=GetPolicy Resource=policy/*
	 */
	public void test_GetPolicy_Allow_Action_Resource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		String userxmlString1 = IAMInterfaceTestUtils.GetPolicy(user2accessKey, user2secretKey, accountId, testPolicy1,
				403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Allow Action=GetPolicy Resource=*
	 */
	public void test_GetPolicy_Allow_Action_Resource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		String userxmlString1 = IAMInterfaceTestUtils.GetPolicy(user2accessKey, user2secretKey, accountId, testPolicy1,
				403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Allow Action=GetPolicy Resource=user/*
	 */
	public void test_GetPolicy_Allow_Action_Resource_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1,
				200);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.GetPolicy(user2accessKey, user2secretKey, accountId, testPolicy1,
				403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString2 = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 200);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow NotAction=GetPolicy Resource=policy/testPolicy1
	 */
	public void test_GetPolicy_Allow_NotAction_Resource_testPolicy1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testPolicy1和testPolicy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 验证除了GetPolicy，其他跟policy相关的操作都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("GetPolicy");
		IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, testPolicy1, policyString, accountId);

		// 和资源不匹配的testPolicy2不允許
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				testPolicy2, policyString, accountId);

		// 验证 跟MFA资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newGroup", testUser1, accountId, "newPolicy", policyString);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"lala_1", tags, policyName, policyString, accountId);
		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * Allow NotAction=GetPolicy Resource=policy/*
	 */
	public void test_GetPolicy_Allow_NotAction_Resource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:GetPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testPolicy1和testPolicy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 验证除了deletePolicy，其他跟policy相关的操作都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("GetPolicy");
		IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, testPolicy1, policyString, accountId);

		IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, testPolicy2, policyString, accountId);

		// 验证 跟MFA资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newGroup", testUser1, accountId, "newPolicy", policyString);
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"lala_1", tags, policyName, policyString, accountId);
		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * Allow NotAction=GetPolicy Resource=*
	 */
	public void test_GetPolicy_Allow_NotAction_Resource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:GetPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testPolicy1和testPolicy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 验证 除了 GetPolicy所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("GetPolicy");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "CreateGroupPolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateGroup"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "newGroup", "mfa2");
	}

	@Test
	/*
	 * Allow Action=GetPolicy NotResource=policy/testPolicy1
	 */
	public void test_GetPolicy_Allow_Action_NotResource_testPolicy1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
	}

	@Test
	/*
	 * Allow Action=GetPolicy NotResource=policy/*
	 */
	public void test_GetPolicy_Allow_Action_NotResource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=GetPolicy NotResource=*
	 */
	public void test_GetPolicy_Allow_Action_NotResource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetPolicy"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));
	}

	@Test
	/*
	 * Allow NotAction=GetPolicy NotResource=policy/testPolicy1
	 */
	public void test_GetPolicy_Allow_NotAction_NotResource_testPolicy1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:GetPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testPolicy1和testPolicy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 资源为testPolicy1的是都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey1, user1secretKey1,
				testPolicy1, policyString, accountId);

		// 验证 跟MFA资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newGroup", "newUser", accountId, "newPolicy", policyString);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * Allow NotAction=GetPolicy NotResource=policy/*
	 */
	public void test_GetPolicy_Allow_NotAction_NotResource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:GetPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testPolicy1和testPolicy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey1, user1secretKey1,
				testPolicy2, policyString, accountId);

		// 验证 跟MFA资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newGroup", "newUser", accountId, "newPolicy", policyString);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * Allow NotAction=GetPolicy NotResource=*
	 */
	public void test_GetPolicy_Allow_NotAction_NotResource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:GetPolicy"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// 删除testPolicy1和删除testPolicy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		String userxmlString = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId,
				testPolicy2, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ testPolicy2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21",
				tags, policyName, policyString, accountId, "newGroup", "mfa3");
	}

	@Test
	/*
	 * Deny Action=GetPolicy Resource=policy/testPolicy1
	 */
	public void test_GetPolicy_Deny_Action_Resource_testPolicy1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

	}

	@Test
	/*
	 * Deny Action=GetPolicy Resource=policy/*
	 */
	public void test_GetPolicy_Deny_Action_Resource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:GetPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

	}

	@Test
	/*
	 * Deny Action=GetPolicy Resource=*
	 */
	public void test_GetPolicy_Deny_Action_Resource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:GetPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

	}

	@Test
	/*
	 * Deny Action=GetPolicy Resource=user/*
	 */
	public void test_GetPolicy_Deny_Action_Resource_resourceNotMatch() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:GetPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

	}

	@Test
	/*
	 * Deny Action=GetPolicy NotResource=policy/testPolicy1
	 */
	public void test_GetPolicy_Deny_Action_NotResource_testPolicy1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:GetPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny Action=GetPolicy NotResource=policy/*
	 */
	public void test_GetPolicy_Deny_Action_NotResource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:GetPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny Action=GetPolicy NotResource=*
	 */
	public void test_GetPolicy_Deny_Action_NotResource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:GetPolicy"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny NotAction=GetPolicy Resource=policy/testPolicy1
	 */
	public void test_GetPolicy_Deny_NotAction_Resource_testPolicy1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny NotAction=GetPolicy Resource=policy/*
	 */
	public void test_GetPolicy_Deny_NotAction_Resource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:GetPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

	}

	@Test
	/*
	 * Deny NotAction=GetPolicy Resource=*
	 */
	public void test_GetPolicy_Deny_NotAction_Resource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:GetPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

	}

	@Test
	/*
	 * Deny NotAction=GetPolicy NotResource=policy/testPolicy1
	 */
	public void test_GetPolicy_Deny_NotAction_NotResource_testPolicy1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:GetPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/" + testPolicy1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

	}

	@Test
	/*
	 * Deny NotAction=GetPolicy NotResource=policy/*
	 */
	public void test_GetPolicy_Deny_NotAction_NotResource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:GetPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	@Test
	/*
	 * Deny NotAction=GetPolicy NotResource=*
	 */
	public void test_GetPolicy_Deny_NotAction_NotResource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:GetPolicy"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, testPolicy2, policyString, 200);

		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 403);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 403);

		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, testPolicy2, 200);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy1, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy1, 200);

		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, testPolicy2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, testPolicy2, 200);

	}

	// attachUserPolicy
	@Test
	/*
	 * Allow Action=AttachUserPolicy Resource=user/testUser1
	 */
	public void test_AttachUserPolicy_Allow_Action_Resource_testUser1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, policyName, 200);

		String userxmlString1 = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		String userxmlString2 = IAMInterfaceTestUtils.AttachUserPolicy(user2accessKey, user2secretKey, accountId,
				testUser1, policyName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=AttachUserPolicy Resource=user/*
	 */
	public void test_AttachUserPolicy_Allow_Action_Resource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, policyName, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, policyName, 200);

		String userxmlString2 = IAMInterfaceTestUtils.AttachUserPolicy(user2accessKey, user2secretKey, accountId,
				testUser1, policyName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=AttachUserPolicy Resource=*
	 */
	public void test_AttachUserPolicy_Allow_Action_Resource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, policyName, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, policyName, 200);

		String userxmlString2 = IAMInterfaceTestUtils.AttachUserPolicy(user2accessKey, user2secretKey, accountId,
				testUser1, policyName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=AttachUserPolicy Resource=policy/*
	 */
	public void test_AttachUserPolicy_Allow_Action_Resource_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String userxmlString = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		String userxmlString2 = IAMInterfaceTestUtils.AttachUserPolicy(user2accessKey, user2secretKey, accountId,
				testUser1, policyName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow NotAction=AttachUserPolicy Resource=user/testUser1
	 */
	public void test_AttachUserPolicy_Allow_NotAction_Resource_testUser1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:AttachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testUser1和testUser2都不允许
		String userxmlString = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		// 验证除了AttachUserPolicy，其他跟user相关的操作都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("AttachUserPolicy");
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				testUser1, tags, "newPolicy1", policyString, accountId);

		// 和资源不匹配的testUser2不允許
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user2secretKey,
				testUser2, tags, "newPolicy2", policyString, accountId);

		// 验证 跟MFA资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newGroup", testUser1, accountId, "newPolicy", policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newPolicy", policyString, accountId);
		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * Allow NotAction=AttachUserPolicy Resource=user/*
	 */
	public void test_AttachUserPolicy_Allow_NotAction_Resource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:AttachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testUser1和testUser2都不允许
		String userxmlString = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		// 验证除了AttachUserPolicy，其他跟user相关的操作都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("AttachUserPolicy");
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				testUser2, tags, "newPolicy2", policyString, accountId);

		// 验证 跟MFA资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newGroup", testUser1, accountId, "newPolicy", policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newPolicy", policyString, accountId);
		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * Allow NotAction=AttachUserPolicy Resource=*
	 */
	public void test_AttachUserPolicy_Allow_NotAction_Resource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:AttachUserPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testUser1和testUser2都不允许
		String userxmlString = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		// 验证 除了 AttachUserPolicy所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("AttachUserPolicy");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "CreateGroupPolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateGroup"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "newGroup", "mfa2");
	}

	@Test
	/*
	 * Allow Action=AttachUserPolicy NotResource=user/testUser1
	 */
	public void test_AttachUserPolicy_Allow_Action_NotResource_testUser1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String userxmlString = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, policyName, 200);
	}

	@Test
	/*
	 * Allow Action=AttachUserPolicy NotResource=user/*
	 */
	public void test_AttachUserPolicy_Allow_Action_NotResource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String userxmlString = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=AttachUserPolicy NotResource=*
	 */
	public void test_AttachUserPolicy_Allow_Action_NotResource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String userxmlString = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));
	}

	@Test
	/*
	 * Allow NotAction=AttachUserPolicy NotResource=user/testUser1
	 */
	public void test_AttachUserPolicy_Allow_NotAction_NotResource_testUser1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:AttachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testUser1和testUser2都不允许
		String userxmlString = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		// 资源为testUser1的是都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey1, user1secretKey1, testUser1,
				tags, "newPolicy", policyString, accountId);

		// 验证 跟MFA资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newGroup", "newUser", accountId, "newPolicy", policyString);
		// 验证 跟policy资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newPolicy1", policyString, accountId);
		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * Allow NotAction=AttachUserPolicy NotResource=user/*
	 */
	public void test_AttachUserPolicy_Allow_NotAction_NotResource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:AttachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policAttachUserPolicyy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testUser1和testUser2都不允许
		String userxmlString = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				testUser2, tags, "newPolicy", policyString, accountId);

		// 验证 跟MFA资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newGroup", "newUser", accountId, "newPolicy", policyString);
		// 验证 跟policy资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newPolicy1", policyString, accountId);
		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * Allow NotAction=AttachUserPolicy NotResource=*
	 */
	public void test_AttachUserPolicy_Allow_NotAction_NotResource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:AttachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testUser1和testuser2都不允许
		String userxmlString = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21",
				tags, policyName, policyString, accountId, "newGroup", "mfa3");
	}

	@Test
	/*
	 * Deny Action=AttachUserPolicy Resource=user/testUser1
	 */
	public void test_AttachUserPolicy_Deny_Action_Resource_testUser1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				403);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, allowPolicy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny Action=AttachUserPolicy Resource=user/*
	 */
	public void test_AttachUserPolicy_Deny_Action_Resource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				403);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, allowPolicy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny Action=AttachUserPolicy Resource=*
	 */
	public void test_AttachUserPolicy_Deny_Action_Resource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				403);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, allowPolicy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny Action=AttachUserPolicy Resource=policy/*
	 */
	public void test_AttachUserPolicy_Deny_Action_Resource_resourceNotMatch() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny Action=AttachUserPolicy NotResource=user/testUser1
	 */
	public void test_AttachUserPolicy_Deny_Action_NotResource_testUser1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				403);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, allowPolicy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny Action=AttachUserPolicy NotResource=user/*
	 */
	public void test_AttachUserPolicy_Deny_Action_NotResource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny Action=AttachUserPolicy NotResource=*
	 */
	public void test_AttachUserPolicy_Deny_Action_NotResource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny NotAction=AttachUserPolicy Resource=user/testUser1
	 */
	public void test_AttachUserPolicy_Deny_NotAction_Resource_testUser1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:AttachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				403);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny NotAction=AttachUserPolicy Resource=user/*
	 */
	public void test_AttachUserPolicy_Deny_NotAction_Resource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:AttachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				403);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				403);
	}

	@Test
	/*
	 * Deny NotAction=AttachUserPolicy Resource=*
	 */
	public void test_AttachUserPolicy_Deny_NotAction_Resource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:AttachUserPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				403);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				403);
	}

	@Test
	/*
	 * Deny NotAction=AttachUserPolicy NotResource=user/testUser1
	 */
	public void test_AttachUserPolicy_Deny_NotAction_NotResource_testUser1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:AttachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				403);
	}

	@Test
	/*
	 * Deny NotAction=AttachUserPolicy NotResource=user/*
	 */
	public void test_AttachUserPolicy_Deny_NotAction_NotResource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:AttachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny NotAction=AttachUserPolicy NotResource=*
	 */
	public void test_AttachUserPolicy_Deny_NotAction_NotResource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:AttachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
	}

	// detachUserPolicy
	@Test
	/*
	 * Allow Action=DetachUserPolicy Resource=user/testUser1
	 */
	public void test_DetachUserPolicy_Allow_Action_Resource_testUser1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		String userxmlString1 = IAMInterfaceTestUtils.DetachUserPolicy(user2accessKey, user2secretKey, accountId,
				testUser1, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, policyName, 200);

		String userxmlString2 = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=DetachUserPolicy Resource=user/*
	 */
	public void test_DetachUserPolicy_Allow_Action_Resource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		String userxmlString1 = IAMInterfaceTestUtils.DetachUserPolicy(user2accessKey, user2secretKey, accountId,
				testUser1, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, policyName, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, policyName, 200);
	}

	@Test
	/*
	 * Allow Action=DetachUserPolicy Resource=*
	 */
	public void test_DetachUserPolicy_Allow_Action_Resource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachUserPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		String userxmlString1 = IAMInterfaceTestUtils.DetachUserPolicy(user2accessKey, user2secretKey, accountId,
				testUser1, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, policyName, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, policyName, 200);
	}

	@Test
	/*
	 * Allow Action=DetachUserPolicy Resource=policy/*
	 */
	public void test_DetachUserPolicy_Allow_Action_Resource_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		String userxmlString1 = IAMInterfaceTestUtils.DetachUserPolicy(user2accessKey, user2secretKey, accountId,
				testUser1, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		String userxmlString2 = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String userxmlString3 = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(userxmlString3);
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error3.get("Message"));
		assertEquals("", error3.get("Resource"));
	}

	@Test
	/*
	 * Allow NotAction=DetachUserPolicy Resource=user/testUser1
	 */
	public void test_DetachUserPolicy_Allow_NotAction_Resource_testUser1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testUser1和testUser2都不允许
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		String userxmlString = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		// 验证除了DetachUserPolicy，其他跟user相关的操作都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("DetachUserPolicy");
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				testUser1, tags, "newPolicy1", policyString, accountId);

		// 和资源不匹配的testUser2不允許
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user2secretKey,
				testUser2, tags, "newPolicy2", policyString, accountId);

		// 验证 跟MFA资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newGroup", testUser1, accountId, "newPolicy", policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newPolicy", policyString, accountId);
		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * Allow NotAction=DetachUserPolicy Resource=user/*
	 */
	public void test_DetachUserPolicy_Allow_NotAction_Resource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testUser1和testUser2都不允许
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		String userxmlString = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		// 验证除了DetachUserPolicy，其他跟user相关的操作都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("DetachUserPolicy");
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUser(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				testUser2, tags, "newPolicy2", policyString, accountId);

		// 验证 跟MFA资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newGroup", testUser1, accountId, "newPolicy", policyString);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newPolicy", policyString, accountId);
		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * Allow NotAction=DetachUserPolicy Resource=*
	 */
	public void test_DetachUserPolicy_Allow_NotAction_Resource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DetachUserPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testUser1和testUser2都不允许
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		String userxmlString = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		// 验证 除了 DetachUserPolicy所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("DetachUserPolicy");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "CreateGroupPolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateGroup"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "newGroup", "mfa2");
	}

	@Test
	/*
	 * Allow Action=DetachUserPolicy NotResource=user/testUser1
	 */
	public void test_DetachUserPolicy_Allow_Action_NotResource_testUser1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		String userxmlString = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, policyName, 200);
	}

	@Test
	/*
	 * Allow Action=DetachUserPolicy NotResource=user/*
	 */
	public void test_DetachUserPolicy_Allow_Action_NotResource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		String userxmlString = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=DetachUserPolicy NotResource=*
	 */
	public void test_DetachUserPolicy_Allow_Action_NotResource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		String userxmlString = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));
	}

	@Test
	/*
	 * Allow NotAction=DetachUserPolicy NotResource=user/testUser1
	 */
	public void test_DetachUserPolicy_Allow_NotAction_NotResource_testUser1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DetachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testUser1和testUser2都不允许
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		String userxmlString = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		// 资源为testUser1的是都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUser(accessKey, secretKey, user1accessKey1, user1secretKey1, testUser1,
				tags, "newPolicy", policyString, accountId);

		// 验证 跟MFA资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newGroup", "newUser", accountId, "newPolicy", policyString);
		// 验证 跟policy资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newPolicy1", policyString, accountId);
		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * Allow NotAction=DetachUserPolicy NotResource=user/*
	 */
	public void test_DetachUserPolicy_Allow_NotAction_NotResource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DetachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policAttachUserPolicyy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testUser1和testUser2都不允许
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		String userxmlString = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				testUser2, tags, "newPolicy", policyString, accountId);

		// 验证 跟MFA资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroupALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newGroup", "newUser", accountId, "newPolicy", policyString);
		// 验证 跟policy资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newPolicy1", policyString, accountId);
		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * Allow NotAction=DetachUserPolicy NotResource=*
	 */
	public void test_DetachUserPolicy_Allow_NotAction_NotResource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DetachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testUser1和testuser2都不允许
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		String userxmlString = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId,
				testUser2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachUserPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ testUser2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, testUser1, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, testUser2, policyName, 200);

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21",
				tags, policyName, policyString, accountId, "newGroup", "mfa3");
	}

	@Test
	/*
	 * Deny Action=DetachUserPolicy Resource=user/testUser1
	 */
	public void test_DetachUserPolicy_Deny_Action_Resource_testUser1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, denyPolicy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				403);
	}

	@Test
	/*
	 * Deny Action=DetachUserPolicy Resource=user/*
	 */
	public void test_DetachUserPolicy_Deny_Action_Resource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, denyPolicy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				403);
	}

	@Test
	/*
	 * Deny Action=DetachUserPolicy Resource=*
	 */
	public void test_DetachUserPolicy_Deny_Action_Resource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DetachUserPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, denyPolicy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				403);
	}

	@Test
	/*
	 * Deny Action=DetachUserPolicy Resource=policy/*
	 */
	public void test_DetachUserPolicy_Deny_Action_Resource_resourceNotMatch() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, denyPolicy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny Action=DetachUserPolicy NotResource=user/testUser1
	 */
	public void test_DetachUserPolicy_Deny_Action_NotResource_testUser1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DetachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, denyPolicy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, denyPolicy, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				403);
	}

	@Test
	/*
	 * Deny Action=DetachUserPolicy NotResource=user/*
	 */
	public void test_DetachUserPolicy_Deny_Action_NotResource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DetachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, denyPolicy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, denyPolicy, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny Action=DetachUserPolicy NotResource=*
	 */
	public void test_DetachUserPolicy_Deny_Action_NotResource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DetachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, denyPolicy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, denyPolicy, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny NotAction=DetachUserPolicy Resource=user/testUser1
	 */
	public void test_DetachUserPolicy_Deny_NotAction_Resource_testUser1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, denyPolicy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, denyPolicy, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				403);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, allowPolicy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny NotAction=DetachUserPolicy Resource=user/*
	 */
	public void test_DetachUserPolicy_Deny_NotAction_Resource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, denyPolicy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, denyPolicy, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				403);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, allowPolicy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				403);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, allowPolicy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny NotAction=DetachUserPolicy Resource=*
	 */
	public void test_DetachUserPolicy_Deny_NotAction_Resource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DetachUserPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, denyPolicy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, denyPolicy, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				403);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, allowPolicy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				403);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, allowPolicy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny NotAction=DetachUserPolicy NotResource=user/testUser1
	 */
	public void test_DetachUserPolicy_Deny_NotAction_NotResource_testUser1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DetachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + testUser1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, denyPolicy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, denyPolicy, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				403);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, allowPolicy, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny NotAction=DetachUserPolicy NotResource=user/*
	 */
	public void test_DetachUserPolicy_Deny_NotAction_NotResource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DetachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, denyPolicy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, denyPolicy, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny NotAction=DetachUserPolicy NotResource=*
	 */
	public void test_DetachUserPolicy_Deny_NotAction_NotResource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DetachUserPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser1, denyPolicy, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, testUser2, denyPolicy, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, denyPolicy, 403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, denyPolicy, 403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachUserPolicy", "iam:DetachUserPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, testUser2, allowPolicy,
				200);
	}

	// attachGroupPolicy
	@Test
	/*
	 * Allow Action=AttachGroupPolicy Resource=group/testGroup1
	 */
	public void test_AttachGroupPolicy_Allow_Action_Resource_testGroup1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/" + testGroup1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, policyName,
				200);

		String userxmlString1 = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		String userxmlString2 = IAMInterfaceTestUtils.AttachGroupPolicy(user2accessKey, user2secretKey, accountId,
				testGroup1, policyName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup1 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=AttachGroupPolicy Resource=group/*
	 */
	public void test_AttachGroupPolicy_Allow_Action_Resource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, policyName,
				200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, policyName,
				200);

		String userxmlString2 = IAMInterfaceTestUtils.AttachGroupPolicy(user2accessKey, user2secretKey, accountId,
				testGroup1, policyName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup1 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=AttachGroupPolicy Resource=*
	 */
	public void test_AttachGroupPolicy_Allow_Action_Resource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, policyName,
				200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, policyName,
				200);

		String userxmlString2 = IAMInterfaceTestUtils.AttachGroupPolicy(user2accessKey, user2secretKey, accountId,
				testGroup1, policyName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup1 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=AttachGroupPolicy Resource=user/*
	 */
	public void test_AttachGroupPolicy_Allow_Action_Resource_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String userxmlString = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		String userxmlString2 = IAMInterfaceTestUtils.AttachGroupPolicy(user2accessKey, user2secretKey, accountId,
				testGroup1, policyName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(userxmlString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup1 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * Allow NotAction=AttachGroupPolicy Resource=group/testGroup1
	 */
	public void test_AttachGroupPolicy_Allow_NotAction_Resource_testGroup1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:AttachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/" + testGroup1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testGroup1和testGroup2都不允许
		String userxmlString = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		// 验证除了AttachGroupPolicy，其他跟group相关的操作都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("AttachGroupPolicy");
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				testGroup1, testUser1, accountId, "newPolicy", policyString);

		// 和资源不匹配的testGroup2不允許
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				testGroup2, "newUser2", accountId, "newPolicy2", policyString);

		// 验证 跟MFA资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user2secretKey,
				"newUser1", tags, "newPolicy3", policyString, accountId);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newPolicy", policyString, accountId);
		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * Allow NotAction=AttachGroupPolicy Resource=group/*
	 */
	public void test_AttachGroupPolicy_Allow_NotAction_Resource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:AttachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testGroup1和testGroup2都不允许
		String userxmlString = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		// 验证除了AttachGroupPolicy，其他跟group相关的操作都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("AttachGroupPolicy");
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				testGroup2, testUser1, accountId, "newPolicy", policyString);

		// 验证 跟MFA资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user2secretKey,
				"newUser1", tags, "newPolicy3", policyString, accountId);
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"newPolicy", policyString, accountId);
		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * Allow NotAction=AttachGroupPolicy Resource=*
	 */
	public void test_AttachGroupPolicy_Allow_NotAction_Resource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:AttachGroupPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testGroup1和testGroup2都不允许
		String userxmlString = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		// 验证 除了 AttachGroupPolicy所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("AttachGroupPolicy");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "CreateGroupPolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:CreateGroup"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "newGroup", "mfa2");
	}

	@Test
	/*
	 * Allow Action=AttachGroupPolicy NotResource=group/testGroup1
	 */
	public void test_AttachGroupPolicy_Allow_Action_NotResource_testGroup1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/" + testGroup1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String userxmlString = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, policyName,
				200);
	}

	@Test
	/*
	 * Allow Action=AttachGroupPolicy NotResource=group/*
	 */
	public void test_AttachGroupPolicy_Allow_Action_NotResource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String userxmlString = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));
	}

	@Test
	/*
	 * Allow Action=AttachGroupPolicy NotResource=*
	 */
	public void test_AttachGroupPolicy_Allow_Action_NotResource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String userxmlString = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));
	}

	@Test
	/*
	 * Allow NotAction=AttachGroupPolicy NotResource=group/testGroup1
	 */
	public void test_AttachGroupPolicy_Allow_NotAction_NotResource_testGroup1() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:AttachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/" + testGroup1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testGroup1和testGroup2都不允许
		String userxmlString = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		// 资源为testGroup1的是都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroup(accessKey, secretKey, user1accessKey1, user1secretKey1,
				testGroup1, testUser1, accountId, "newPolicy", policyString);

		// 验证 跟MFA资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newUser", tags, "newPolicy1", policyString, accountId);
		// 验证 跟policy资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newPolicy1", policyString, accountId);
		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * Allow NotAction=AttachGroupPolicy NotResource=group/*
	 */
	public void test_AttachGroupPolicy_Allow_NotAction_NotResource_all() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:AttachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policAttachUserPolicyy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testGroup1和testGroup2都不允许
		String userxmlString = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				testGroup2, testUser1, accountId, "newPolicy", policyString);

		// 验证 跟MFA资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "mfa1");
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newUser", tags, "policy", policyString, accountId);
		// 验证 跟policy资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"newPolicy1", policyString, accountId);
		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * Allow NotAction=AttachGroupPolicy NotResource=*
	 */
	public void test_AttachGroupPolicy_Allow_NotAction_NotResource_all2() throws JSONException {
		// 创建policy
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:AttachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		// testGroup1和testGroup2都不允许
		String userxmlString = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup1, policyName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(userxmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup1 + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String userxmlString1 = IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				testGroup2, policyName, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(userxmlString1);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:AttachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ testGroup2 + ".", error1.get("Message"));
		assertEquals("", error1.get("Resource"));

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21",
				tags, policyName, policyString, accountId, "newGroup", "mfa3");
	}

	@Test
	/*
	 * Deny Action=AttachGroupPolicy Resource=group/testGroup1
	 */
	public void test_AttachGroupPolicy_Deny_Action_Resource_testGroup1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/" + testGroup1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, denyPolicy,
				403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy", "iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, testGroup1, allowPolicy, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny Action=AttachGroupPolicy Resource=group/*
	 */
	public void test_AttachGroupPolicy_Deny_Action_Resource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, denyPolicy,
				403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy", "iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, testGroup1, allowPolicy, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny Action=AttachGroupPolicy Resource=*
	 */
	public void test_AttachGroupPolicy_Deny_Action_Resource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, denyPolicy,
				403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy", "iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, testGroup1, allowPolicy, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny Action=AttachGroupPolicy Resource=user/*
	 */
	public void test_AttachGroupPolicy_Deny_Action_Resource_resourceNotMatch() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, denyPolicy,
				403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy", "iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny Action=AttachGroupPolicy NotResource=group/testGroup1
	 */
	public void test_AttachGroupPolicy_Deny_Action_NotResource_testGroup1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/" + testGroup1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, denyPolicy,
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, denyPolicy,
				403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy", "iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, testGroup2, allowPolicy, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny Action=AttachGroupPolicy NotResource=group/*
	 */
	public void test_AttachGroupPolicy_Deny_Action_NotResource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, denyPolicy,
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, denyPolicy,
				403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy", "iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny Action=AttachGroupPolicy NotResource=*
	 */
	public void test_AttachGroupPolicy_Deny_Action_NotResource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, denyPolicy,
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, denyPolicy,
				403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy", "iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny NotAction=AttachGroupPolicy Resource=group/testGroup1
	 */
	public void test_AttachGroupPolicy_Deny_NotAction_Resource_testGroup1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:AttachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/" + testGroup1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, denyPolicy,
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, denyPolicy,
				403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy", "iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				403);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny NotAction=AttachGroupPolicy Resource=group/*
	 */
	public void test_AttachGroupPolicy_Deny_NotAction_Resource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:AttachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, denyPolicy,
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, denyPolicy,
				403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy", "iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				403);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				403);
	}

	@Test
	/*
	 * Deny NotAction=AttachGroupPolicy Resource=*
	 */
	public void test_AttachGroupPolicy_Deny_NotAction_Resource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:AttachGroupPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, denyPolicy,
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, denyPolicy,
				403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy", "iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				403);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				403);
	}

	@Test
	/*
	 * Deny NotAction=AttachGroupPolicy NotResource=group/testGroup1
	 */
	public void test_AttachGroupPolicy_Deny_NotAction_NotResource_testGroup1() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:AttachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/" + testGroup1), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, denyPolicy,
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, denyPolicy,
				403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy", "iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				403);
	}

	@Test
	/*
	 * Deny NotAction=AttachGroupPolicy NotResource=group/*
	 */
	public void test_AttachGroupPolicy_Deny_NotAction_NotResource_all() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:AttachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, denyPolicy,
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, denyPolicy,
				403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy", "iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				200);
	}

	@Test
	/*
	 * Deny NotAction=AttachGroupPolicy NotResource=*
	 */
	public void test_AttachGroupPolicy_Deny_NotAction_NotResource_all2() throws JSONException {
		// 创建policy
		String denyPolicy = "denyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:AttachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, denyPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, denyPolicy, 200);

		// 拒绝
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, denyPolicy,
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, denyPolicy,
				403);

		// 创建policy
		String allowPolicy = "allowPolicy";
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:AttachGroupPolicy", "iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, allowPolicy, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, allowPolicy, 200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup1, allowPolicy,
				200);

		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, testGroup2, allowPolicy,
				200);
	}

	// =======================DetachGroupPolicy================================================

	@Test
	/*
	 * 1.allow Action=DetachGroupPolicy, resource=group/group1 只允许detach group1
	 */
	public void test_DetachGroupPolicy_Allow_Action_group1() throws JSONException {
		// 创建policy
		String policyName = "DetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);

		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		String user2xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user2accessKey, user2secretKey, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * 2.allow Action=DetachGroupPolicy, resource=group/* 可以detach所有group的策略
	 */
	public void test_DetachGroupPolicy_Allow_Action_all() throws JSONException {
		// 创建policy
		String policyName = "DetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);

		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		String user2xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user2accessKey, user2secretKey, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				200);

	}

	@Test
	/*
	 * 3.allow Action=DetachGroupPolicy, resource=* 可以detach所有组的策略
	 */
	public void test_DetachGroupPolicy_Allow_Action_all2() throws JSONException {
		// 创建policy
		String policyName = "DetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);

		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		String user2xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user2accessKey, user2secretKey, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				200);
	}

	@Test
	/*
	 * a.allow Action=DetachGroupPolicy, resource=user/* 资源和请求的action不匹配，policy不生效
	 */
	public void test_DetachGroupPolicy_Allow_Action_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyName = "DetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "ak_test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		// 验证请求
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		String user2xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user2accessKey, user2secretKey, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error3.get("Message"));
		assertEquals("", error3.get("Resource"));
	}

	@Test
	/*
	 * 4.allow NotAction=DetachGroupPolicy, resource=group/group1
	 * 资源resource只能匹配除了DetachGroupPolicy的其他group1相关操作
	 */
	public void test_DetachGroupPolicy_Allow_NotAction_group1() throws JSONException {
		// 创建策略
		String policyName = "DetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给用户添加policy
		String userName = "ak_test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		// user1 detech组1、组2都不允许
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了DetachGroupPolicy其他相关的方法都允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy66", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				403);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		// 和资源不匹配的group2不允许
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy66",
				403);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 403);

		// user1 ListPolicies, resource not match
		body = "Action=ListPolicies&Version=2010-05-08";
		Pair<Integer, String> listGroupPolicieslist2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1,
				user1secretKey1);
		assertEquals(403, listGroupPolicieslist2.first().intValue());
		JSONObject error4 = IAMTestUtils.ParseErrorToJson(listGroupPolicieslist2.second());
		assertEquals("AccessDenied", error4.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error4.get("Message"));
		assertEquals("", error4.get("Resource"));

		// 验证 跟mfa资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
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

	}

	@Test
	/*
	 * 5.allow NotAction=DetachGroupPolicy, resource=group/*
	 * 资源resource只能匹配除了DetachGroupPolicy的其他group相关操作
	 */
	public void test_DetachGroupPolicy_Allow_NotAction_policyall() throws JSONException {
		//
		String policyName = "DetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "ak_test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		// user1 detech组1、组2都不允许
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了DetachGroupPolicy其他相关的方法都允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy66", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				403);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);

		// 验证 跟mfa资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
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
	 * 6.allow NotAction=DetachGroupPolicy, resource=* 可匹配除了DetachGroupPolicy的所有其他操作
	 */
	public void test_DetachGroupPolicy_Allow_NotAction_all() throws JSONException {
		// 创建策略
		String userName = "ak_test_1";
		String policyName = "DetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
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

		// user1 detech组1、组2都不允许
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了DetachGroupPolicy所有方法都允許，验证时需要注释掉工具方法内的deleteGroup和deletePolicy
		List<String> excludes = new ArrayList<String>();
		excludes.add("DetachGroupPolicy");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "DetachGroupPolicyPolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "group1", "mfa2");
	}

	@Test
	/*
	 * 7.allow Action=DetachGroupPolicy, NotResource=group/group1
	 * 允许DetachGroupPolicy 但是资源是非group/group1
	 */
	public void test_DetachGroupPolicy_Allow_Action_notgroup1() throws JSONException {
		// 创建policy
		String policyName = "DetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String detachGroupPolicyString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1,
				accountId, groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(detachGroupPolicyString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				200);
	}

	@Test
	/*
	 * 8.allow Action=DetachGroupPolicy, NotResource=group/* 允许DetachGroupPolicy
	 * 但是资源是非group/*
	 */
	public void test_DetachGroupPolicy_Allow_Action_NotgroupALL() throws JSONException {
		// 创建policy
		String policyName = "DetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String detachGroupPolicyString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1,
				accountId, groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(detachGroupPolicyString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String detachGroupPolicyString2 = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1,
				accountId, groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(detachGroupPolicyString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * 9.allow Action=DetachGroupPolicy, NotResource:* 允许DetachGroupPolicy 但是资源是非*
	 */
	public void test_DetachGroupPolicy_Allow_Action_NotALL() throws JSONException {
		// 创建policy
		String policyName = "DetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String detachGroupPolicyString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1,
				accountId, groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(detachGroupPolicyString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String detachGroupPolicyString2 = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1,
				accountId, groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(detachGroupPolicyString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * 10.allow NotAction=DetachGroupPolicy, NotResource=group/group1
	 * 允许非DetachGroupPolicy 但是资源是非group/group1
	 */
	public void test_DetachGroupPolicy_Allow_NotAction_Notgroup1() throws JSONException {
		// 创建policy
		String policyName = "DetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// user1 detech组1、组2都不允许
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 资源为group/group1的是都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy66", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				403);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				403);
		// listVirtualMFADevices,允许
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);

		// 验证 跟mfa资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				policyName1, policyString1, accountId);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);

	}

	@Test
	/*
	 * 11.allow NotAction=DetachGroupPolicy, NotResource=group/*
	 * 允许非DetachGroupPolicy 但是资源是非group/*
	 */
	public void test_DetachGroupPolicy_Allow_NotAction_NotpolicyALL() throws JSONException {
		// 创建policy
		String policyName = "DetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证detach group1、group2的策略都不允许
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 资源为group/*的是都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy66", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				403);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				403);
		// listVirtualMFADevices,允许
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);

		// 验证 跟mfa资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				policyName1, policyString1, accountId);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * 12.allow NotAction=DetachGroupPolicy, NotResource=* 允许非DetachGroupPolicy
	 * 但是资源是非*
	 */
	public void test_DetachGroupPolicy_Allow_NotAction_NotALL() throws JSONException {
		// 创建policy
		String policyName = "DetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证detach group1、group2的策略都不允许
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

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
	 * 13.Deny Action=DetachGroupPolicy, resource=group/group1 显示拒绝detach group1的策略
	 */
	public void test_DetachGroupPolicy_Deny_Action_group1() {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyDetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				403);

		String policyName2 = "AllowDetachGroupPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建detach group1的Policy，但有权限做其他操作
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				403);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy66", 200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);

	}

	@Test
	/*
	 * 14.Deny Action=DetachGroupPolicy, resource=group/*
	 */
	public void test_DetachGroupPolicy_Deny_Action_groupall() {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyDetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				403);

		String policyName2 = "AllowDetachGroupPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建detach group1的Policy，但有权限做其他操作
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				403);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy66", 200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);

	}

	@Test
	/*
	 * 15.Deny Action=DetachGroupPolicy, resource=*
	 */
	public void test_DetachGroupPolicy_Deny_Action_all() {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyDetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				403);

		String policyName2 = "AllowDetachGroupPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建detach group1的Policy，但有权限做其他操作
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				403);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy66", 200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);

	}

	@Test
	/*
	 * b.Deny Action=DetachGroupPolicy, resource=user/* 资源不匹配，deny失败
	 */
	public void test_DetachGroupPolicy_Deny_Action_ReourceNotMatch() {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyDetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝资源不匹配未生效
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				403);

		String policyName2 = "AllowDetachGroupPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建detach group1的Policy，但有权限做其他操作
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);

		// 显示拒绝未生效，有显示允许，user1可以做所有操作
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);
	}

	@Test
	/*
	 * 16.Deny Action=DetachGroupPolicy, NotResource=group/group1
	 * 资源非group1,显示拒绝group1失效，显示拒绝group2生效
	 */
	public void test_DetachGroupPolicy_Deny_Action_NotResouce_group1() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyDetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 一个隐式拒绝，一个显式拒绝
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowDetachGroupPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝group1失效
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);

		// 显示拒绝group2生效
		String detachGroupPolicy2String2 = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1,
				accountId, groupName2, "testpolicy88", 403);
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(detachGroupPolicy2String2);
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error3.get("Message"));
		assertEquals("", error3.get("Resource"));

	}

	@Test
	/*
	 * 17.Deny Action=DetachGroupPolicy, NotResource=group/*
	 */
	public void test_DetachGroupPolicy_Deny_Action_NotResouce_groupAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyDetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowDetachGroupPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝group1失效
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);

		// 显示拒绝group2生效
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				200);

	}

	@Test
	/*
	 * 18.Deny Action=DetachGroupPolicy, NotResource=*
	 */
	public void test_DetachGroupPolicy_Deny_Action_NotResouce_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyDetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowDetachGroupPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝group1失效
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);

		// 显示拒绝group2生效
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				200);

	}

	@Test
	/*
	 * 19.Deny NotAction=DetachGroupPolicy, Resource=group/group1
	 */
	public void test_DetachGroupPolicy_Deny_NotAction_Resource_group1() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyDetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowDetachGroupPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除detach以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy66", 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);

		// 显示拒绝group2失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);

	}

	@Test
	/*
	 * 20.Deny NotAction=DetachGroupPolicy, Resource=group/*
	 */
	public void test_DetachGroupPolicy_Deny_NotAction_Resource_groupAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyDetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowDetachGroupPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除detach以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy66", 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);

		// 显示拒绝除detach以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy66",
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy66", 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);

	}

	@Test
	/*
	 * 21.Deny NotAction=DetachGroupPolicy, Resource=*
	 */
	public void test_DetachGroupPolicy_Deny_NotAction_Resource_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyDetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowDetachGroupPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除detach以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString2, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy66", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy66", 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 403);

		// 显示拒绝除detach以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString2, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy66", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy66",
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy66", 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 403);

	}

	@Test
	/*
	 * 22.Deny NotAction=DetachGroupPolicy, NotResource=group/group1
	 */
	public void test_DetachGroupPolicy_Deny_NotAction_NotResource_group1() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyDetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowDetachGroupPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString2, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy66", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 403);

		// 显示拒绝group2
		// IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1,
		// "testpolicy66", policyString2, 403);
		// IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy66",
		// policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy66",
				403);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy66", 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 403);
	}

	@Test
	/*
	 * 23.Deny NotAction=DetachGroupPolicy, NotResource=group/*
	 */
	public void test_DetachGroupPolicy_Deny_NotAction_NotResource_groupAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyDetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowDetachGroupPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString2, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy66", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 403);

		// 显示拒绝group2
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString2, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy66", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 403);
	}

	@Test
	/*
	 * 24.Deny NotAction=DetachGroupPolicy, NotResource=*
	 */
	public void test_DetachGroupPolicy_Deny_NotAction_NotResource_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyDetachGroupPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName2, "testpolicy88", 200);
		String user1xmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName, "testpolicy88", 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId,
				groupName2, "testpolicy88", 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:DetachGroupPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowDetachGroupPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);

		// 显示拒绝group2失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy66", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy66", 200);

	}

	@Test
	/*
	 * c.在IP范围的允许访问
	 */
	public void test_DetachGroupPolicy_Condition_sourceIP() {
		String userName = user1Name;
		String policyName = "allowspecialIP";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.168.1.1/24")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 在IP范围
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		String policyArn = "arn:ctyun:iam::" + accountId + ":policy/testpolicy88";
		String body = "Action=DetachGroupPolicy&Version=2010-05-08&GroupName=" + groupName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
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
	public void test_DetachGroupPolicy_Condition_username() {
		String userName = "ak_test_1";
		String policyName = "allowUsername";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("ak_test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// username 符合条件
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		String policyArn = "arn:ctyun:iam::" + accountId + ":policy/testpolicy88";
		String body = "Action=DetachGroupPolicy&Version=2010-05-08&GroupName=" + groupName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		// username 不符合条件
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		policyArn = "arn:ctyun:iam::" + accountId + ":policy/testpolicy88";
		body = "Action=DetachGroupPolicy&Version=2010-05-08&GroupName=" + groupName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(body, user3accessKey, user3secretKey);
		assertEquals(403, result3.first().intValue());
	}

	@Test
	/*
	 * e.符合实际条件允许访问
	 */
	public void test_DetachGroupPolicy_Condition_CurrentTime() {
		String userName = "ak_test_1";
		String policyName = "allowDateGreate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2019-01-01T00:00:00Z")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 时间符合条件
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		String policyArn = "arn:ctyun:iam::" + accountId + ":policy/testpolicy88";
		String body = "Action=DetachGroupPolicy&Version=2010-05-08&GroupName=" + groupName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2050-01-01T00:00:00Z")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 时间不符合条件
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * f.设置不允许ssl访问
	 */
	public void test_DetachGroupPolicy_Condition_SecureTransport() {
		String userName = "ak_test_1";
		String policyName = "DenySSL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 允许ssl访问
		String policyString88 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString88, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		String policyArn = "arn:ctyun:iam::" + accountId + ":policy/testpolicy88";
		String body = "Action=DetachGroupPolicy&Version=2010-05-08&GroupName=" + groupName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("false")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:DetachGroupPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 不允许ssl访问
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "testpolicy88", 200);
		policyArn = "arn:ctyun:iam::" + accountId + ":policy/testpolicy88";
		body = "Action=DetachGroupPolicy&Version=2010-05-08&GroupName=" + groupName2 + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());

	}

	// =======================ListAttachedUserPolicies================================================

	@Test
	/*
	 * 1.allow Action=ListAttachedUserPolicies, resource=user/user1 只允许list user1
	 */
	public void test_ListAttachedUserPolicies_Allow_Action_user1() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/ak_test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 200);

		String user2xmlString = IAMInterfaceTestUtils.ListAttachedUserPolicies(user2accessKey, user2secretKey, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/ak_test_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		String user1bxmlString = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1,
				user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/ak_test_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * 2.allow Action=ListAttachedUserPolicies, resource=user/* 可以list所有user的策略
	 */
	public void test_ListAttachedUserPolicies_Allow_Action_all() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 200);

		String user2xmlString = IAMInterfaceTestUtils.ListAttachedUserPolicies(user2accessKey, user2secretKey, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/ak_test_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, user2Name, 200);

	}

	@Test
	/*
	 * 3.allow Action=ListAttachedUserPolicies, resource=* 所有组可以list策略
	 */
	public void test_ListAttachedUserPolicies_Allow_Action_all2() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 200);

		String user2xmlString = IAMInterfaceTestUtils.ListAttachedUserPolicies(user2accessKey, user2secretKey, userName,
				403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/ak_test_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, user2Name, 200);

	}

	@Test
	/*
	 * a.allow Action=ListAttachedUserPolicies, resource=group/*
	 * 资源和请求的action不匹配，policy不生效
	 */
	public void test_ListAttachedUserPolicies_Allow_Action_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "ak_test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		// 验证请求
		String user1xmlString = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1,
				userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/ak_test_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		String user2xmlString = IAMInterfaceTestUtils.ListAttachedUserPolicies(user2accessKey, user2secretKey, userName,
				403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/ak_test_1.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String user1bxmlString = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1,
				user2Name, 403);
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/ak_test_2.",
				error3.get("Message"));
		assertEquals("", error3.get("Resource"));
	}

	@Test
	/*
	 * 4.allow NotAction=ListAttachedUserPolicies, resource=user/user1
	 * 资源resource只能匹配除了ListAttachedUserPolicies的其他user1相关操作
	 */
	public void test_ListAttachedUserPolicies_Allow_NotAction_user1() throws JSONException {
		// 创建策略
		String policyName = "ListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/ak_test_1"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给用户添加policy
		String userName = "ak_test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		// user1 list用户1、用户2都不允许
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了ListAttachedUserPolicies其他相关的方法都允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy66", policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 403);
		// 和资源不匹配的group2不允许
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, "testpolicy66",
				403);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, user2Name, 403);

		// user1 ListPolicies, resource not match
		body = "Action=ListPolicies&Version=2010-05-08";
		Pair<Integer, String> listGroupPolicieslist2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1,
				user1secretKey1);
		assertEquals(403, listGroupPolicieslist2.first().intValue());
		JSONObject error4 = IAMTestUtils.ParseErrorToJson(listGroupPolicieslist2.second());
		assertEquals("AccessDenied", error4.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error4.get("Message"));
		assertEquals("", error4.get("Resource"));

		// 验证 跟mfa资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyName, policyString, accountId);
		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"testgroup88", userName, accountId, policyName, policyString);

		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 5.allow NotAction=ListAttachedUserPolicies, resource=user/*
	 * 资源resource只能匹配除了ListAttachedUserPolicies的其他user相关操作
	 */
	public void test_ListAttachedUserPolicies_Allow_NotAction_userall() throws JSONException {
		//
		String policyName = "ListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "ak_test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		// user1 list用户1、用户2都不允许
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了ListAttachedUserPolicies其他相关的方法都允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy66", policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 403);

		// user1 ListPolicies, resource not match
		body = "Action=ListPolicies&Version=2010-05-08";
		Pair<Integer, String> listGroupPolicieslist2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1,
				user1secretKey1);
		assertEquals(403, listGroupPolicieslist2.first().intValue());
		JSONObject error4 = IAMTestUtils.ParseErrorToJson(listGroupPolicieslist2.second());
		assertEquals("AccessDenied", error4.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error4.get("Message"));
		assertEquals("", error4.get("Resource"));

		// 验证 跟mfa资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
		// 验证 跟policy资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyName, policyString, accountId);
		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"testgroup88", userName, accountId, policyName, policyString);

		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 6.allow NotAction=ListAttachedUserPolicies, resource=*
	 * 可匹配除了ListAttachedUserPolicies的所有其他操作
	 */
	public void test_ListAttachedUserPolicies_Allow_NotAction_all() throws JSONException {
		// 创建策略
		String userName = "ak_test_1";
		String policyName = "ListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
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

		// user1 list用户1、用户2都不允许
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了ListAttachedUserPolicies所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("ListAttachedUserPolicies");
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "ListAttachedUserPoliciesPolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "group1", "mfa2");
	}

	@Test
	/*
	 * 7.allow Action=ListAttachedUserPolicies, NotResource=user/user1
	 * 允许ListAttachedUserPolicies 但是资源是非user/user1
	 */
	public void test_ListAttachedUserPolicies_Allow_Action_notuser1() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/ak_test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String listUserPoliciesString = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1,
				userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPoliciesString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, user2Name, 200);
	}

	@Test
	/*
	 * 8.allow Action=ListAttachedUserPolicies, NotResource=user/*
	 * 允许ListAttachedUserPolicies 但是资源是非user/*
	 */
	public void test_ListAttachedUserPolicies_Allow_Action_NotuserALL() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String listUserPoliciesString = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1,
				userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPoliciesString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String listUserPoliciesString2 = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPoliciesString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * 9.allow Action=ListAttachedUserPolicies, NotResource:*
	 * 允许ListAttachedUserPolicies 但是资源是非*
	 */
	public void test_ListAttachedUserPolicies_Allow_Action_NotALL() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String listUserPoliciesString = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1,
				userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPoliciesString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String listUserPoliciesString2 = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPoliciesString2);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * 10.allow NotAction=ListAttachedUserPolicies, NotResource=user/user1
	 * 允许非ListAttachedUserPolicies 但是资源是非user/user1
	 */
	public void test_ListAttachedUserPolicies_Allow_NotAction_Notuser1() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedUserPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/ak_test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// user1 list用户1、用户2都不允许
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了user1的操作都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy66", policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy66",
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy66",
				403);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 403);
		// 和资源不匹配的user2允许
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, "testpolicy66",
				200);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, user2Name, 403);

		// listVirtualMFADevices,允许
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);

		// 验证 跟mfa资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/groupName_1"), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				policyName1, policyString1, accountId);
		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"testgroup88", userName, accountId, policyName, policyString);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);

	}

	@Test
	/*
	 * 11.allow NotAction=ListAttachedUserPolicies, NotResource=user/*
	 * 允许非ListAttachedUserPolicies 但是资源是非user/*
	 */
	public void test_ListAttachedUserPolicies_Allow_NotAction_NotuserALL() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedUserPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// user1 list用户1、用户2都不允许
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了user1的操作都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy66", policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy66",
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy66",
				403);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 403);

		// listVirtualMFADevices,允许
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);

		// 验证 跟mfa资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/groupName_1"), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				policyName1, policyString1, accountId);
		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"testgroup88", userName, accountId, policyName, policyString);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * 12.allow NotAction=ListAttachedUserPolicies, NotResource=*
	 * 允许非ListAttachedUserPolicies 但是资源是非*
	 */
	public void test_ListAttachedUserPolicies_Allow_NotAction_NotALL() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedUserPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// user1 list用户1、用户2都不允许
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

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
	 * 13.Deny Action=ListAttachedUserPolicies, resource=user/user1 显示拒绝list
	 * user1的策略
	 */
	public void test_ListAttachedUserPolicies_Deny_Action_user1() {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/ak_test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 403);

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建list user1的策略，但有权限做其他操作
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 403);

	}

	@Test
	/*
	 * 14.Deny Action=ListAttachedUserPolicies, resource=user/*
	 */
	public void test_ListAttachedUserPolicies_Deny_Action_groupall() {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 403);

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建list user1的策略，但有权限做其他操作
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 403);

	}

	@Test
	/*
	 * 15.Deny Action=ListAttachedUserPolicies, resource=*
	 */
	public void test_ListAttachedUserPolicies_Deny_Action_all() {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 403);

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建list user1的策略，但有权限做其他操作
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 403);

	}

	@Test
	/*
	 * b.Deny Action=ListAttachedUserPolicies, resource=group/* 资源不匹配，deny失败
	 */
	public void test_ListAttachedUserPolicies_Deny_Action_ReourceNotMatch() {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝资源不匹配未生效
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 403);

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝未生效，有显示允许，user1可以做所有操作
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 200);

	}

	@Test
	/*
	 * 16.Deny Action=ListAttachedUserPolicies, NotResource=user/user1
	 * 资源非user1,显示拒绝user1失效，显示拒绝user2生效
	 */
	public void test_ListAttachedUserPolicies_Deny_Action_NotResouce_user1() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/ak_test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 一个隐式拒绝，一个显式拒绝
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝user1失效
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 200);

		// 显示拒绝user2生效
		String listUserPolicies2String2 = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String2);
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error3.get("Message"));
		assertEquals("", error3.get("Resource"));

	}

	@Test
	/*
	 * 17.Deny Action=ListAttachedUserPolicies, NotResource=user/*
	 */
	public void test_ListAttachedUserPolicies_Deny_Action_NotResouce_userAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝user1失效
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 200);

		// 显示拒绝user2生效
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, user2Name, 200);

	}

	@Test
	/*
	 * 18.Deny Action=ListAttachedUserPolicies, NotResource=*
	 */
	public void test_ListAttachedUserPolicies_Deny_Action_NotResouce_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝user1失效
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 200);

		// 显示拒绝user2生效
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, user2Name, 200);

	}

	@Test
	/*
	 * 19.Deny NotAction=ListAttachedUserPolicies, Resource=user/user1
	 */
	public void test_ListAttachedUserPolicies_Deny_NotAction_Resource_user1() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/ak_test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				403);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

		// 显示拒绝user2失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, user2Name, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

	}

	@Test
	/*
	 * 20.Deny NotAction=ListAttachedUserPolicies, Resource=user/*
	 */
	public void test_ListAttachedUserPolicies_Deny_NotAction_Resource_userAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				403);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, "testpolicy88",
				403);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, user2Name, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

	}

	@Test
	/*
	 * 21.Deny NotAction=ListAttachedUserPolicies, Resource=*
	 */
	public void test_ListAttachedUserPolicies_Deny_NotAction_Resource_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				403);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 403);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, "testpolicy88",
				403);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, user2Name, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);

	}

	@Test
	/*
	 * 22.Deny NotAction=ListAttachedUserPolicies, NotResource=user/user1
	 */
	public void test_ListAttachedUserPolicies_Deny_NotAction_NotResource_user1() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedUserPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/ak_test_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);

		// 显示拒绝group2失效
		// IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1,
		// "testpolicy88", policyString2, 403);
		// IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88",
		// policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, "testpolicy88",
				403);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, user2Name, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);
	}

	@Test
	/*
	 * 23.Deny NotAction=ListAttachedUserPolicies, NotResource=user/*
	 */
	public void test_ListAttachedUserPolicies_Deny_NotAction_NotResource_userAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedUserPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);

		// 显示拒绝group2失效
		// IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1,
		// "testpolicy88", policyString2, 403);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, user2Name, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);

	}

	@Test
	/*
	 * 24.Deny NotAction=ListAttachedUserPolicies, NotResource=*
	 */
	public void test_ListAttachedUserPolicies_Deny_NotAction_NotResource_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedUserPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedUserPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String listUserPolicies1String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, userName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listUserPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ userName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listUserPolicies2String = IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1,
				user1secretKey1, user2Name, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listUserPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedUserPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:user/"
				+ user2Name + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, userName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

		// 显示拒绝group2失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedUserPolicies(user1accessKey1, user1secretKey1, user2Name, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

	}

	@Test
	/*
	 * c.在IP范围的允许访问
	 */
	public void test_ListAttachedUserPolicies_Condition_sourceIP() {
		String userName = user1Name;
		String policyName = "allowspecialIP";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.168.1.1/24")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 在IP范围
		String body = "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName=" + userName;
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
	public void test_ListAttachedUserPolicies_Condition_username() {
		String userName = "ak_test_1";
		String policyName = "allowUsername";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("ak_test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// username 符合条件
		String body = "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName=" + userName;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		// username 不符合条件
		body = "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName=" + user3Name;
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(body, user3accessKey, user3secretKey);
		assertEquals(403, result3.first().intValue());
	}

	@Test
	/*
	 * e.符合实际条件允许访问
	 */
	public void test_ListAttachedUserPolicies_Condition_CurrentTime() {
		String userName = "ak_test_1";
		String policyName = "allowDateGreate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2019-01-01T00:00:00Z")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 时间符合条件
		String body = "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName=" + userName;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2050-01-01T00:00:00Z")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
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
	public void test_ListAttachedUserPolicies_Condition_SecureTransport() {
		String userName = "ak_test_1";
		String policyName = "DenySSL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 允许ssl访问
		String body = "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName=" + userName;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("false")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedUserPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 不允许ssl访问
		body = "Action=ListAttachedUserPolicies&Version=2010-05-08&UserName=" + user2Name;
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());

	}

	// ======================ListAttachedGroupPolicies================================================

	@Test
	/*
	 * 1.allow Action=ListAttachedGroupPolicies, resource=group/group1 只允许list
	 * group1
	 */
	public void test_ListAttachedGroupPolicies_Allow_Action_group1() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);

		String user2xmlString = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user2accessKey, user2secretKey,
				groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		String user1bxmlString = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1,
				groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * 2.allow Action=ListAttachedGroupPolicies, resource=group/* 可以list所有group的策略
	 */
	public void test_ListAttachedGroupPolicies_Allow_Action_all() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);

		String user2xmlString = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user2accessKey, user2secretKey,
				groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 200);

	}

	@Test
	/*
	 * 3.allow Action=ListAttachedGroupPolicies, resource=* 所有组可以list策略
	 */
	public void test_ListAttachedGroupPolicies_Allow_Action_all2() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);

		String user2xmlString = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user2accessKey, user2secretKey,
				groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 200);
	}

	@Test
	/*
	 * a.allow Action=ListAttachedGroupPolicies, resource=user/*
	 * 资源和请求的action不匹配，policy不生效
	 */
	public void test_ListAttachedGroupPolicies_Allow_Action_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "ak_test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		// 验证请求
		String user1xmlString = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1,
				groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		String user2xmlString = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user2accessKey, user2secretKey,
				groupName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_1.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String user1bxmlString = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1,
				groupName2, 403);
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/testGroup_2.",
				error3.get("Message"));
		assertEquals("", error3.get("Resource"));
	}

	@Test
	/*
	 * 4.allow NotAction=ListAttachedGroupPolicies, resource=group/group1
	 * 资源resource只能匹配除了ListAttachedGroupPolicies的其他group1相关操作
	 */
	public void test_ListAttachedGroupPolicies_Allow_NotAction_group1() throws JSONException {
		// 创建策略
		String policyName = "ListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给用户添加policy
		String userName = "ak_test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		// user1创建list组1、组2都不允许
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了ListAttachedGroupPolicies其他相关的方法都允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		// 和资源不匹配的group2不允许
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				403);

		// user1 ListPolicies, resource not match
		body = "Action=ListPolicies&Version=2010-05-08";
		Pair<Integer, String> listGroupPolicieslist2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1,
				user1secretKey1);
		assertEquals(403, listGroupPolicieslist2.first().intValue());
		JSONObject error4 = IAMTestUtils.ParseErrorToJson(listGroupPolicieslist2.second());
		assertEquals("AccessDenied", error4.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error4.get("Message"));
		assertEquals("", error4.get("Resource"));

		// 验证 跟mfa资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
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
	 * 5.allow NotAction=ListAttachedGroupPolicies, resource=group/*
	 * 资源resource只能匹配除了ListAttachedGroupPolicies的其他group相关操作
	 */
	public void test_ListAttachedGroupPolicies_Allow_NotAction_policyall() throws JSONException {
		//
		String policyName = "ListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "ak_test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		// 验证user1创建VirtualMFADevice1 VirtualMFADevice2都不允许
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了 ListAttachedGroupPolicies其他跟group/*相关的方法都允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);

		// 验证 跟mfa资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
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
	 * 6.allow NotAction=ListAttachedGroupPolicies, resource=*
	 * 可匹配除了ListAttachedGroupPolicies的所有其他操作
	 */
	public void test_ListAttachedGroupPolicies_Allow_NotAction_all() throws JSONException {
		// 创建策略
		String userName = "ak_test_1";
		String policyName = "ListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
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

		// 验证user1创建VirtualMFADevice1 VirtualMFADevice2都不允许
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了ListAttachedGroupPolicies所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("ListAttachedGroupPolicies");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "ListAttachedGroupPoliciesPolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "group1", "mfa2");
	}

	@Test
	/*
	 * 7.allow Action=ListAttachedGroupPolicies, NotResource=group/group1
	 * 允许ListAttachedGroupPolicies 但是资源是非group/group1
	 */
	public void test_ListAttachedGroupPolicies_Allow_Action_notgroup1() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String listGroupPoliciesString = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPoliciesString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 200);
	}

	@Test
	/*
	 * 8.allow Action=ListAttachedGroupPolicies, NotResource=group/*
	 * 允许ListAttachedGroupPolicies 但是资源是非group/*
	 */
	public void test_ListAttachedGroupPolicies_Allow_Action_NotgroupALL() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * 9.allow Action=ListAttachedGroupPolicies, NotResource:*
	 * 允许ListAttachedGroupPolicies 但是资源是非*
	 */
	public void test_ListAttachedGroupPolicies_Allow_Action_NotALL() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * 10.allow NotAction=ListAttachedGroupPolicies, NotResource=group/group1
	 * 允许非ListAttachedGroupPolicies 但是资源是非group/group1
	 */
	public void test_ListAttachedGroupPolicies_Allow_NotAction_Notgroup1() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证创list group1、group2的策略都不允许
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 资源为group/group1的是都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				403);
		// listVirtualMFADevices,允许
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);

		// 验证 跟mfa资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				policyName1, policyString1, accountId);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);

	}

	@Test
	/*
	 * 11.allow NotAction=ListAttachedGroupPolicies, NotResource=group/*
	 * 允许非ListAttachedGroupPolicies 但是资源是非group/*
	 */
	public void test_ListAttachedGroupPolicies_Allow_NotAction_NotpolicyALL() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证创list group1、group2的策略都不允许
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 资源为group/*的是都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				403);
		// listVirtualMFADevices,允许
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);

		// 验证 跟mfa资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFA(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
		// 验证 跟policy资源相关接口都允许
		String policyName1 = "testPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				policyName1, policyString1, accountId);
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * 12.allow NotAction=ListAttachedGroupPolicies, NotResource=*
	 * 允许非ListAttachedGroupPolicies 但是资源是非*
	 */
	public void test_ListAttachedGroupPolicies_Allow_NotAction_NotALL() throws JSONException {
		// 创建policy
		String policyName = "ListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证创建group1 和group2都不允许
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

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
	 * 13.Deny Action=ListAttachedGroupPolicies, resource=group/group1 显示拒绝list
	 * group1的策略
	 */
	public void test_ListAttachedGroupPolicies_Deny_Action_group1() {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 403);

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建list group1的策略，但有权限做其他操作
		List<String> excludes = new ArrayList<String>();
		excludes.add("ListAttachedGroupPolicies");
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

	}

	@Test
	/*
	 * 14.Deny Action=ListAttachedGroupPolicies, resource=group/*
	 */
	public void test_ListAttachedGroupPolicies_Deny_Action_groupall() {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 403);

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建list group1的策略，但有权限做其他操作
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

	}

	@Test
	/*
	 * 15.Deny Action=ListAttachedGroupPolicies, resource=*
	 */
	public void test_ListAttachedGroupPolicies_Deny_Action_all() {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 403);

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建list group1的策略，但有权限做其他操作
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

	}

	@Test
	/*
	 * b.Deny Action=ListAttachedGroupPolicies, resource=user/* 资源不匹配，deny失败
	 */
	public void test_ListAttachedGroupPolicies_Deny_Action_ReourceNotMatch() {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝资源不匹配未生效
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 403);

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝未生效，有显示允许，user1可以做所有操作
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
	}

	@Test
	/*
	 * 16.Deny Action=ListAttachedGroupPolicies, NotResource=group/group1
	 * 资源非group1,显示拒绝group1失效，显示拒绝group2生效
	 */
	public void test_ListAttachedGroupPolicies_Deny_Action_NotResouce_group1() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 一个隐式拒绝，一个显式拒绝
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝group1失效
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);

		// 显示拒绝group2生效
		String listGroupPolicies2String2 = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String2);
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error3.get("Message"));
		assertEquals("", error3.get("Resource"));

	}

	@Test
	/*
	 * 17.Deny Action=ListAttachedGroupPolicies, NotResource=group/*
	 */
	public void test_ListAttachedGroupPolicies_Deny_Action_NotResouce_groupAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝group1失效
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);

		// 显示拒绝group2失效
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 200);

	}

	@Test
	/*
	 * 18.Deny Action=ListAttachedGroupPolicies, NotResource=*
	 */
	public void test_ListAttachedGroupPolicies_Deny_Action_NotResouce_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝group1失效
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);

		// 显示拒绝group2失效
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 200);

	}

	@Test
	/*
	 * 19.Deny NotAction=ListAttachedGroupPolicies, Resource=group/group1
	 */
	public void test_ListAttachedGroupPolicies_Deny_NotAction_Resource_group1() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				403);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

		// 显示拒绝group2失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

	}

	@Test
	/*
	 * 20.Deny NotAction=ListAttachedGroupPolicies, Resource=group/*
	 */
	public void test_ListAttachedGroupPolicies_Deny_NotAction_Resource_groupAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				403);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

		// 显示拒绝group2失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				403);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

	}

	@Test
	/*
	 * 21.Deny NotAction=ListAttachedGroupPolicies, Resource=*
	 */
	public void test_ListAttachedGroupPolicies_Deny_NotAction_Resource_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				403);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);

		// 显示拒绝group2失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 403);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				403);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);

	}

	@Test
	/*
	 * 22.Deny NotAction=ListAttachedGroupPolicies, NotResource=group/group1
	 */
	public void test_ListAttachedGroupPolicies_Deny_NotAction_NotResource_group1() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup_1"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);

		// 显示拒绝group2失效
		// IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1,
		// "testpolicy88", policyString2, 403);
		// IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88",
		// policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				403);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				403);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);
	}

	@Test
	/*
	 * 23.Deny NotAction=ListAttachedGroupPolicies, NotResource=group/*
	 */
	public void test_ListAttachedGroupPolicies_Deny_NotAction_NotResource_groupAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);

		// 显示拒绝group2失效
		// IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1,
		// "testpolicy88", policyString2, 403);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 403);

	}

	@Test
	/*
	 * 24.Deny NotAction=ListAttachedGroupPolicies, NotResource=*
	 */
	public void test_ListAttachedGroupPolicies_Deny_NotAction_NotResource_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListAttachedGroupPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝创建设备
		String listGroupPolicies1String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(listGroupPolicies1String);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String listGroupPolicies2String = IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1,
				user1secretKey1, groupName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(listGroupPolicies2String);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListAttachedGroupPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:group/"
				+ groupName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListAttachedGroupPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

		// 显示拒绝group2失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "testpolicy88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				200);
		IAMInterfaceTestUtils.DetachGroupPolicy(user1accessKey1, user1secretKey1, accountId, groupName2, "testpolicy88",
				200);
		IAMInterfaceTestUtils.ListAttachedGroupPolicies(user1accessKey1, user1secretKey1, groupName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "testpolicy88", 200);

	}

	@Test
	/*
	 * c.在IP范围的允许访问
	 */
	public void test_ListAttachedGroupPolicies_Condition_sourceIP() {
		String userName = user1Name;
		String policyName = "allowspecialIP";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.168.1.1/24")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 在IP范围
		String body = "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName=" + groupName;
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
	public void test_ListAttachedGroupPolicies_Condition_username() {
		String userName = "ak_test_1";
		String policyName = "allowUsername";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("ak_test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// username 符合条件
		String body = "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName=" + groupName;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		// username 不符合条件
		body = "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName=" + groupName2;
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(body, user3accessKey, user3secretKey);
		assertEquals(403, result3.first().intValue());
	}

	@Test
	/*
	 * e.符合实际条件允许访问
	 */
	public void test_ListAttachedGroupPolicies_Condition_CurrentTime() {
		String userName = "ak_test_1";
		String policyName = "allowDateGreate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2019-01-01T00:00:00Z")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 时间符合条件
		String body = "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName=" + groupName;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2050-01-01T00:00:00Z")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 时间不符合条件
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * f.设置不允许ssl访问
	 */
	public void test_ListAttachedGroupPolicies_Condition_SecureTransport() {
		String userName = "ak_test_1";
		String policyName = "DenySSL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 允许ssl访问
		String body = "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName=" + groupName;
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("false")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListAttachedGroupPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 不允许ssl访问
		body = "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName=" + groupName2;
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());

	}

	// =======================ListEntitiesForPolicy===============================================

	@Test
	/*
	 * 1.allow Action=ListEntitiesForPolicy, resource=policy/policy1 只允许list policy1
	 */
	public void test_ListEntitiesForPolicy_Allow_Action_policy1() throws JSONException {
		// 创建policy
		String policyName = "ListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/policytest01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);

		String user2xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user2accessKey, user2secretKey, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * 2.allow Action=ListEntitiesForPolicy, resource=policy/* 可以list所有policy
	 */
	public void test_ListEntitiesForPolicy_Allow_Action_all() throws JSONException {
		// 创建policy
		String policyName = "ListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);

		String user2xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user2accessKey, user2secretKey, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 200);

	}

	@Test
	/*
	 * 3.allow Action=ListEntitiesForPolicy, resource=* 可以list所有policy
	 */
	public void test_ListEntitiesForPolicy_Allow_Action_all2() throws JSONException {
		// 创建policy
		String policyName = "ListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);

		String user2xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user2accessKey, user2secretKey, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 200);
	}

	@Test
	/*
	 * a.allow Action=ListEntitiesForPolicy, resource=user/*
	 * 资源和请求的action不匹配，policy不生效
	 */
	public void test_ListEntitiesForPolicy_Allow_Action_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyName = "ListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "ak_test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String user2xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user2accessKey, user2secretKey, accountId,
				policyTestName, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error3.get("Message"));
		assertEquals("", error3.get("Resource"));
	}

	@Test
	/*
	 * 4.allow NotAction=ListEntitiesForPolicy, resource=policy/policy1
	 * 资源resource只能匹配除了ListEntitiesForPolicy的其他policy相关操作
	 */
	public void test_ListEntitiesForPolicy_Allow_NotAction_policy1() throws JSONException {
		// 创建策略
		String policyName = "ListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/policytest01"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		// 给用户添加policy
		String userName = "ak_test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// user1 list策略1、策略2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了ListEntitiesForPolicy其他跟policy/policy1相关的方法都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("ListEntitiesForPolicy");
		IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, policyTestName, policyString, accountId);
		// 和资源不匹配的mfaDevice2不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyTestName2, policyString, accountId);

		// ListPolicies, resource not match
		body = "Action=ListPolicies&Version=2010-05-08";
		Pair<Integer, String> policyList = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, policyList.first().intValue());
		JSONObject error3 = IAMTestUtils.ParseErrorToJson(policyList.second());
		assertEquals("AccessDenied", error3.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error3.get("Message"));
		assertEquals("", error3.get("Resource"));

		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟mfa资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
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
	 * 5.allow NotAction=ListEntitiesForPolicy, resource=policy/*
	 * 资源resource只能匹配除了ListEntitiesForPolicy的其他policy相关操作
	 */
	public void test_ListEntitiesForPolicy_Allow_NotAction_policyall() throws JSONException {
		//
		String policyName = "ListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "ak_test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// user1 list策略1、策略2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了 ListEntitiesForPolicy其他跟policy/*相关的方法都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("ListEntitiesForPolicy");
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, "policytest88", policyString, accountId);

		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟mfa资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"ak_test_11", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 6.allow NotAction=ListEntitiesForPolicy, resource=*
	 * 可匹配除了ListEntitiesForPolicy的所有其他操作
	 */
	public void test_ListEntitiesForPolicy_Allow_NotAction_all() throws JSONException {
		// 创建策略
		String userName = "ak_test_1";
		String policyName = "ListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
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

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// user1 list策略1、策略2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了 CreateVirtualMFADevice所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("ListEntitiesForPolicy");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "ListEntitiesForPolicyPolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "group1", "mfa2");
	}

	@Test
	/*
	 * 7.allow Action=ListEntitiesForPolicy, NotResource=policy/policy1
	 * 允许ListEntitiesForPolicy 但是资源是非policy/policy1
	 */
	public void test_ListEntitiesForPolicy_Allow_Action_notPolicy1() throws JSONException {
		// 创建policy
		String policyName = "ListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/policytest01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 200);
	}

	@Test
	/*
	 * 8.allow Action=ListEntitiesForPolicy, NotResource=policy/*
	 * 允许ListEntitiesForPolicy 但是资源是非policy/*
	 */
	public void test_ListEntitiesForPolicy_Allow_Action_NotPolicyALL() throws JSONException {
		// 创建policy
		String policyName = "ListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * 9.allow Action=ListEntitiesForPolicy, NotResource:* 允许ListEntitiesForPolicy
	 * 但是资源是非*
	 */
	public void test_ListEntitiesForPolicy_Allow_Action_NotALL() throws JSONException {
		// 创建policy
		String policyName = "ListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 验证请求
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * 10.allow NotAction=ListEntitiesForPolicy, NotResource=policy/policy1
	 * 允许非ListEntitiesForPolicy 但是资源是非policy/policy1
	 */
	public void test_ListEntitiesForPolicy_Allow_NotAction_NotPolicy1() throws JSONException {
		// 创建policy
		String policyName = "ListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListEntitiesForPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/policytest01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 验证list policy1和policy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 资源为policy/policy1的是都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicy(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyTestName, policyString, accountId);
		// user1 ListMFADevices, 允许
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟mfa资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);

	}

	@Test
	/*
	 * 11.allow NotAction=ListEntitiesForPolicy, NotResource=policy/*
	 * 允许非ListEntitiesForPolicy 但是资源是非policy/*
	 */
	public void test_ListEntitiesForPolicy_Allow_NotAction_NotPolicyALL() throws JSONException {
		// 创建policy
		String policyName = "ListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListEntitiesForPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 验证list policy1和policy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证资源是policy/*的都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"policytest88", policyString, accountId);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟mfa资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * 12.allow NotAction=ListEntitiesForPolicy, NotResource=*
	 * 允许非ListEntitiesForPolicy 但是资源是非*
	 */
	public void test_ListEntitiesForPolicy_Allow_NotAction_NotALL() throws JSONException {
		// 创建policy
		String policyName = "ListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListEntitiesForPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 验证list policy1和policy2都不允许
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

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
	 * 13.Deny Action=ListEntitiesForPolicy, resource=policy/policy1 显示拒绝创建policy1
	 */
	public void test_ListEntitiesForPolicy_Deny_Action_policy1() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/policytest01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 显示拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建ListEntitiesForPolicy，但有权限做其他操作
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 403);

		List<String> excludes = new ArrayList<String>();
		excludes.add("ListEntitiesForPolicy");
		IAMInterfaceTestUtils.AllowActionResourcePolicy(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, policyTestName, policyString2, accountId);

	}

	@Test
	/*
	 * 14.Deny Action=ListEntitiesForPolicy, resource=policy/*
	 */
	public void test_ListEntitiesForPolicy_Deny_Action_policyall() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 显示拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建ListEntitiesForPolicy，但有权限做其他操作
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 403);

		List<String> excludes = new ArrayList<String>();
		excludes.add("ListEntitiesForPolicy");
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, policyTestName, policyString2, accountId);
	}

	@Test
	/*
	 * 15.Deny Action=ListEntitiesForPolicy, resource=*
	 */
	public void test_ListEntitiesForPolicy_Deny_Action_all() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 显示拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限创建ListEntitiesForPolicy，但有权限做其他操作
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "policytest01", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "policytest01", 200);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, "policytest01", 403);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, "policytest01", 403);
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "policytest01", 200);
	}

	@Test
	/*
	 * b.Deny Action=ListEntitiesForPolicy, resource=user/* 资源不匹配，deny失败
	 */
	public void test_ListEntitiesForPolicy_Deny_Action_ReourceNotMatch() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 显示拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝未生效，有显示允许，user1可以进行所有操作
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"policyTestName01", policyString, accountId);
	}

	@Test
	/*
	 * 16.Deny Action=ListEntitiesForPolicy, NotResource=policy/policy1
	 * 资源非policy1,显示拒绝policy1失效，显示拒绝policy2生效
	 */
	public void test_ListEntitiesForPolicy_Deny_Action_NotResource_policy1() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/policytest01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝list policy1失效
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);

		// 显示拒绝list policy2生效
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 403);

	}

	@Test
	/*
	 * 17.Deny Action=ListEntitiesForPolicy, NotResource=policy/*
	 */
	public void test_ListEntitiesForPolicy_Deny_Action_NotResouce_policyAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝list policy1失效
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);

		// 显示拒绝list policy2失效
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 200);

	}

	@Test
	/*
	 * 18.Deny Action=ListEntitiesForPolicy, NotResource=*
	 */
	public void test_ListEntitiesForPolicy_Deny_Action_NotResouce_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 一个隐式拒绝，一个显式拒绝
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝list policy1失效
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);

		// 显示拒绝list policy2失效
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 200);

	}

	@Test
	/*
	 * 19.Deny NotAction=ListEntitiesForPolicy, Resource=policy/policy1
	 * resource为policy/policy1时，拒绝除ListEntitiesForPolicy以外的操作
	 */
	public void test_ListEntitiesForPolicy_Deny_NotAction_Resource_mfa1() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/policytest01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyTestName2, 200);

		String policyName2 = "AllowListEntitiesForPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, policyTestName, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, policyTestName, policyString, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName,
				200);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);

		// 显示拒绝policy2失效
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, policyTestName2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName2,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName2,
				200);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 200);
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);

	}

	@Test
	/*
	 * 20.Deny NotAction=ListEntitiesForPolicy, Resource=policy/*
	 */
	public void test_ListEntitiesForPolicy_Deny_NotAction_Resource_policyAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyTestName2, 200);

		String policyName2 = "AllowListEntitiesForPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, policyTestName, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, policyTestName, policyString, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName,
				200);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, policyTestName2, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, policyTestName2, policyString, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName2,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName2,
				200);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 200);
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
	}

	@Test
	/*
	 * 21.Deny NotAction=ListEntitiesForPolicy, Resource=*
	 */
	public void test_ListEntitiesForPolicy_Deny_NotAction_Resource_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyTestName2, 200);

		String policyName2 = "AllowListEntitiesForPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, policyTestName, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, policyTestName, policyString, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName,
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName,
				403);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, policyTestName2, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, policyTestName2, policyString, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName2,
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName2,
				403);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 200);
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);

	}

	@Test
	/*
	 * 22.Deny NotAction=ListEntitiesForPolicy, NotResource=policy/policy1
	 */
	public void test_ListEntitiesForPolicy_Deny_NotAction_NotResource_policy1() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListEntitiesForPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/policytest01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyTestName2, 200);

		String policyName2 = "AllowListEntitiesForPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 资源为policy1的操作都允许
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName,
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName,
				403);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);

		// 资源为policy2的除list外都拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, policyTestName2, policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, policyTestName2, policyString, 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName2,
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName2,
				403);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 200);
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);

	}

	@Test
	/*
	 * 23.Deny NotAction=ListEntitiesForPolicy, NotResource=policy/*
	 */
	public void test_ListEntitiesForPolicy_Deny_NotAction_NotResource_policyAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListEntitiesForPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyTestName2, 200);

		String policyName2 = "AllowListEntitiesForPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 资源为policy1的操作都允许
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName,
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName,
				403);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);

		// 资源为policy2的除list外都拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, policyTestName2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName2,
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName2,
				403);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 200);
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);

	}

	@Test
	/*
	 * 24.Deny NotAction=ListEntitiesForPolicy, NotResource=*
	 */
	public void test_ListEntitiesForPolicy_Deny_NotAction_NotResource_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListEntitiesForPolicyPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListEntitiesForPolicy"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 隐式拒绝创建设备
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName2, policyString, 200);
		String user1xmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId,
				policyTestName, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName + ".", error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user1bxmlString = IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1,
				accountId, policyTestName2, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user1bxmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/"
				+ policyTestName2 + ".", error2.get("Message"));
		assertEquals("", error2.get("Resource"));
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyTestName2, 200);

		String policyName2 = "AllowListEntitiesForPolicyPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy",
						"iam:ListPolicies"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 资源为policy1的操作都允许
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, policyTestName, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName,
				200);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName, 200);
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);

		// 资源为policy2的除list外都拒绝
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, policyTestName2, policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName2,
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, user2Name, policyTestName2,
				200);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user1accessKey1, user1secretKey1, accountId, policyTestName2, 200);
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);
	}

	@Test
	/*
	 * c.在IP范围的允许访问
	 */
	public void test_ListEntitiesForPolicy_Condition_sourceIP() {
		String userName = user1Name;
		String policyName = "allowspecialIP";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.168.1.1/24")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 在IP范围
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		String policyArn = "arn:ctyun:iam::" + accountId + ":policy/" + policyTestName;
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=" + UrlEncoded.encodeString(policyArn);
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
	public void test_ListEntitiesForPolicy_Condition_username() {
		String userName = "ak_test_1";
		String policyName = "allowUsername";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("ak_test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// username 符合条件
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		String policyArn = "arn:ctyun:iam::" + accountId + ":policy/" + policyTestName;
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=" + UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		// username 不符合条件
		policyArn = "arn:ctyun:iam::" + accountId + ":policy/" + policyTestName;
		body = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=" + UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(body, user3accessKey, user3secretKey);
		assertEquals(403, result3.first().intValue());
	}

	@Test
	/*
	 * e.符合实际条件允许访问
	 */
	public void test_ListEntitiesForPolicy_Condition_CurrentTime() {
		String userName = "ak_test_1";
		String policyName = "allowDateGreate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2019-01-01T00:00:00Z")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 时间符合条件
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		String policyArn = "arn:ctyun:iam::" + accountId + ":policy/" + policyTestName;
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=" + UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2050-01-01T00:00:00Z")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 时间不符合条件
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * f.设置不允许ssl访问
	 */
	public void test_ListEntitiesForPolicy_Condition_SecureTransport() {
		String userName = "ak_test_1";
		String policyName = "DenySSL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		String policyTestName = "policytest01";
		String policyTestName2 = "policytest02";

		// 允许ssl访问
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyTestName, policyString, 200);
		String policyArn = "arn:ctyun:iam::" + accountId + ":policy/" + policyTestName;
		String body = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=" + UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("false")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListEntitiesForPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 不允许ssl访问
		body = "Action=ListEntitiesForPolicy&Version=2010-05-08&PolicyArn=" + UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());

	}

	// ==========================ListPolicies======================================================

	/*
	 * 1.allow Action=ListPolicies, resource=policy/policy1
	 * ListPolicies匹配的资源只有policy/*,该项测试用例没有意义
	 */

	@Test
	/*
	 * 2.allow Action=ListPolicies, resource=policy/* 可以list policy
	 */
	public void test_ListPolicies_Allow_Action_all() throws JSONException {
		// 创建policy
		String policyName = "ListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);

		String user2xmlString = IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

	}

	@Test
	/*
	 * 3.allow Action=ListPolicies, resource=* 可以list所有policy，与resource为policy/*情况相同
	 */
	public void test_ListPolicies_Allow_Action_all2() throws JSONException {
		// 创建policy
		String policyName = "ListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 200);

		String user2xmlString = IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

	}

	@Test
	/*
	 * a.allow Action=ListPolicies, resource=user/* 资源和请求的action不匹配，policy不生效
	 */
	public void test_ListPolicies_Allow_Action_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyName = "ListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"),
				null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "ak_test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		// 验证请求
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		String user2xmlString = IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	/*
	 * 4.allow NotAction=ListPolicies, resource=policy/policy1
	 * ListPolicies匹配的资源只有policy/*,该项测试用例没有意义
	 */

	@Test
	/*
	 * 5.allow NotAction=ListPolicies, resource=policy/*
	 * 资源resource只能匹配除了ListPolicies的其他policy相关操作
	 */
	public void test_ListPolicies_Allow_NotAction_policyall() throws JSONException {
		//
		String policyName = "ListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + policyName + "&PolicyDocument="
				+ UrlEncoded.encodeString(policyString);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());

		// 给用户添加policy
		String userName = "ak_test_1";
		String policyArn = "arn:ctyun:iam::3rmoqzn03g6ga:policy/" + policyName;
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ UrlEncoded.encodeString(policyArn);
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result2.first().intValue());

		// 验证user1 user2都不允许ListPolicies
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user2xmlString = IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了 ListPolicies其他跟policy/*相关的方法都允许
		List<String> excludes = new ArrayList<String>();
		excludes.add("ListPolicies");
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, "policyTestName01", policyString, accountId);

		// 验证 跟group资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceGroupALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟mfa资源相关接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceMFAALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
		// 验证 跟user资源相关接口都不允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceUserALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				"ak_test_11", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都不允许
		IAMInterfaceTestUtils.DenyActionResourceOthers(user1accessKey1, user1accessKey1);
	}

	@Test
	/*
	 * 6.allow NotAction=ListPolicies, resource=* 可匹配除了ListPolicies的所有其他操作
	 */
	public void test_ListPolicies_Allow_NotAction_all() throws JSONException {
		// 创建策略
		String userName = "ak_test_1";
		String policyName = "ListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListPolicies"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
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

		// 验证user1创建VirtualMFADevice1 VirtualMFADevice2都不允许
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user2xmlString = IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证 除了 ListPolicies所有方法都允許
		List<String> excludes = new ArrayList<String>();
		excludes.add("ListPolicies");

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		String policyName2 = "ListPoliciesPolicy2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListPolicies"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);

		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
				"test_7", tags, policyName2, policyString2, accountId, "group1", "mfa2");
	}

	/*
	 * 7.allow Action=ListPolicies, NotResource=policy/policy1
	 * ListPolicies匹配的资源只有policy/*,该项测试用例没有意义
	 */

	@Test
	/*
	 * 8.allow Action=ListPolicies, NotResource=policy/* 允许ListPolicies
	 * 但是资源是非policy/*
	 */
	public void test_ListPolicies_Allow_Action_NotPolicyALL() throws JSONException {
		// 创建policy
		String policyName = "ListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		String user2xmlString = IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	@Test
	/*
	 * 9.allow Action=ListPolicies, NotResource:* 允许ListPolicies 但是资源是非*
	 */
	public void test_ListPolicies_Allow_Action_NotALL() throws JSONException {
		// 创建policy
		String policyName = "ListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证请求
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		String user2xmlString = IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));
	}

	/*
	 * 10.allow NotAction=ListPolicies, NotResource=policy/policy1
	 * ListPolicies匹配的资源只有policy/*,该项测试用例没有意义
	 */

	@Test
	/*
	 * 11.allow NotAction=ListPolicies, NotResource=policy/* 允许非ListPolicies
	 * 但是资源是非policy/*
	 */
	public void test_ListPolicies_Allow_NotAction_NotPolicyALL() throws JSONException {
		// 创建policy
		String policyName = "ListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证user1 user2都不允许list policy
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user2xmlString = IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		// 验证资源是policy/*的都不允许
		IAMInterfaceTestUtils.DenyActionResourcePolicyALL(accessKey, secretKey, user1accessKey1, user1secretKey1,
				policyName, policyString, accountId);

		// 验证 跟group资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceGroup(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"group1", userName, accountId, policyName, policyString);
		// 验证 跟mfa资源相关接口都允许
		IAMInterfaceTestUtils.AllowActionResourceMFAALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				accountId, "testMFADevice01");
		// 验证 跟user资源相关接口都允许
		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.AllowActionResourceUserALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"lala_18", tags, policyName, policyString, accountId);

		// 验证 其他资源不匹配接口都允许
		IAMInterfaceTestUtils.AllowActionResourceOthers(user1accessKey1, user1secretKey1, null);
	}

	@Test
	/*
	 * 12.allow NotAction=ListPolicies, NotResource=* 允许非ListPolicies 但是资源是非*
	 */
	public void test_ListPolicies_Allow_NotAction_NotALL() throws JSONException {
		// 创建policy
		String policyName = "ListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:ListPolicies"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		String userName = "ak_test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 验证user1 user2都不允许list policy
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user2xmlString = IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
		tags.add(tag);
		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_21",
				tags, policyName, policyString, accountId, "group1", "mfa3");
	}

	/*
	 * 13.Deny Action=ListPolicies, resource=policy/policy1
	 * ListPolicies匹配的资源只有policy/*,该项测试用例没有意义
	 */

	@Test
	/*
	 * 14.Deny Action=ListPolicies, resource=policy/*
	 */
	public void test_ListPolicies_Deny_Action_policyall() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限ListPolicies，但有其他权限
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);

		List<String> excludes = new ArrayList<String>();
		excludes.add("ListPolicies");
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, "policyTestName01", policyString, accountId);
	}

	@Test
	/*
	 * 15.Deny Action=ListPolicies, resource=* 允许除了ListPolicies以外的所有请求
	 */
	public void test_ListPolicies_Deny_Action_all() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝优先，user1没有权限ListPolicies，但有其他权限
		IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);

		List<String> excludes = new ArrayList<String>();
		excludes.add("ListPolicies");
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, excludes, user1accessKey1,
				user1secretKey1, "policyTestName01", policyString, accountId);
	}

	@Test
	/*
	 * b.Deny Action=ListPolicies, resource=user/* 资源不匹配，deny失败
	 */
	public void test_ListPolicies_Deny_Action_ReourceNotMatch() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝资源不匹配未生效
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:ListPolicies", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝未生效，有显示允许，user1所有请求都被允许
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"policyTestName01", policyString, accountId);
	}

	/*
	 * 16.Deny Action=ListPolicies, NotResource=policy/policy1
	 * ListPolicies匹配的资源只有policy/*,该项测试用例没有意义
	 */

	@Test
	/*
	 * 17.Deny Action=ListPolicies, NotResource=policy/*
	 * 拒绝ListPolicies，前提是资源非policy/*
	 */
	public void test_ListPolicies_Deny_Action_NotResouce_policyAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:ListPolicies", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// user1都允许
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"policyTestName01", policyString, accountId);

		// user2
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, "policyTestName01", policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user2accessKey, user2secretKey, accountId, "policyTestName01", 200);
		IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 200);
		IAMInterfaceTestUtils.ListEntitiesForPolicy(user2accessKey, user2secretKey, accountId, "policyTestName01", 200);
		IAMInterfaceTestUtils.DeletePolicy(user2accessKey, user2secretKey, accountId, "policyTestName01", 200);

	}

	@Test
	/*
	 * 18.Deny Action=ListPolicies, NotResource=*
	 */
	public void test_ListPolicies_Deny_Action_NotResouce_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:ListPolicies", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);

		// 显示拒绝user1失效
		IAMInterfaceTestUtils.AllowActionResourcePolicyALL(accessKey, secretKey, null, user1accessKey1, user1secretKey1,
				"policyTestName01", policyString, accountId);

	}

	/*
	 * 19.Deny NotAction=ListPolicies, Resource=policy/policy1
	 * ListPolicies匹配的资源只有policy/*,该项测试用例没有意义
	 */

	@Test
	/*
	 * 20.Deny NotAction=ListPolicies, Resource=policy/*
	 */
	public void test_ListPolicies_Deny_NotAction_Resource_policyAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user2xmlString = IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "policytest88", policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "policytest88", policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "policytest88", 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "policytest88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "policytest88",
				200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "policytest88", 403);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "policytest88", 200);

		// 没attach拒绝策略，允许所有方法
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, "policytest88", policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user2accessKey, user2secretKey, accountId, "policytest88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user2accessKey, user2secretKey, accountId, user2Name, "policytest88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user2accessKey, user2secretKey, accountId, user2Name, "policytest88",
				200);
		IAMInterfaceTestUtils.DeletePolicy(user2accessKey, user2secretKey, accountId, "policytest88", 200);
	}

	@Test
	/*
	 * 21.Deny NotAction=ListPolicies, Resource=* 拒绝ListPolicies以外所有请求
	 */
	public void test_ListPolicies_Deny_NotAction_Resource_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user2xmlString = IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除list以外的方法
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "policytest88", policyString, 403);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, "policytest88", policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "policytest88", 403);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "policytest88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "policytest88",
				200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "policytest88", 403);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "policytest88", 200);

		// 没attach拒绝策略，允许所有方法
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, "policytest88", policyString, 200);
		IAMInterfaceTestUtils.GetPolicy(user2accessKey, user2secretKey, accountId, "policytest88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user2accessKey, user2secretKey, accountId, user2Name, "policytest88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user2accessKey, user2secretKey, accountId, user2Name, "policytest88",
				200);
		IAMInterfaceTestUtils.DeletePolicy(user2accessKey, user2secretKey, accountId, "policytest88", 200);
	}

	/*
	 * 22.Deny NotAction=ListPolicies, NotResource=policy/policy1
	 * ListPolicies匹配的资源只有policy/*,该项测试用例没有意义
	 */

	@Test
	/*
	 * 23.Deny NotAction=ListPolicies, NotResource=policy/*
	 * 拒绝除ListPolicies，资源是非policy/*的所有请求
	 */
	public void test_ListPolicies_Deny_NotAction_NotResource_policyAll() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListPolicies"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user2xmlString = IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除list以外的方法，但资源不能是policy/*
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "policytest88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "policytest88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "policytest88",
				403);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "policytest88",
				403);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "policytest88", 200);

		// 没attach拒绝策略，允许所有方法
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, "policytest88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user2accessKey, user2secretKey, accountId, "policytest88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user2accessKey, user2secretKey, accountId, user2Name, "policytest88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user2accessKey, user2secretKey, accountId, user2Name, "policytest88",
				200);
		IAMInterfaceTestUtils.DeletePolicy(user2accessKey, user2secretKey, accountId, "policytest88", 200);

	}

	@Test
	/*
	 * 24.Deny NotAction=ListPolicies, NotResource=*
	 */
	public void test_ListPolicies_Deny_NotAction_NotResource_All() throws JSONException {
		String userName = "ak_test_1";
		// 创建policy
		String policyName = "DenyListPoliciesPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:ListPolicies"), "NotResource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 隐式拒绝
		String user1xmlString = IAMInterfaceTestUtils.ListPolicies(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error.get("Message"));
		assertEquals("", error.get("Resource"));
		String user2xmlString = IAMInterfaceTestUtils.ListPolicies(user2accessKey, user2secretKey, 403);
		JSONObject error2 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error2.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:ListPolicies on resource: arn:ctyun:iam::3rmoqzn03g6ga:policy/*.",
				error2.get("Message"));
		assertEquals("", error2.get("Resource"));

		String policyName2 = "AllowListPoliciesPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:AttachUserPolicy",
						"iam:DetachUserPolicy", "iam:AttachGroupPolicy", "iam:DetachGroupPolicy",
						"iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListEntitiesForPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝除list以外的方法，但资源是非*（没有意义）
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, "policytest88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user1accessKey1, user1secretKey1, accountId, "policytest88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "policytest88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user1accessKey1, user1secretKey1, accountId, userName, "policytest88",
				200);
		IAMInterfaceTestUtils.DeletePolicy(user1accessKey1, user1secretKey1, accountId, "policytest88", 200);

		// 没attach拒绝策略，允许所有方法
		IAMInterfaceTestUtils.CreatePolicy(user2accessKey, user2secretKey, "policytest88", policyString2, 200);
		IAMInterfaceTestUtils.GetPolicy(user2accessKey, user2secretKey, accountId, "policytest88", 200);
		IAMInterfaceTestUtils.AttachUserPolicy(user2accessKey, user2secretKey, accountId, user2Name, "policytest88",
				200);
		IAMInterfaceTestUtils.DetachUserPolicy(user2accessKey, user2secretKey, accountId, user2Name, "policytest88",
				200);
		IAMInterfaceTestUtils.DeletePolicy(user2accessKey, user2secretKey, accountId, "policytest88", 200);

	}

	@Test
	/*
	 * c.在IP范围的允许访问
	 */
	public void test_ListPolicies_Condition_sourceIP() {
		String userName = user1Name;
		String policyName = "allowspecialIP";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.168.1.1/24")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 在IP范围
		String body = "Action=ListPolicies&Version=2010-05-08";
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
	public void test_ListPolicies_Condition_username() {
		String userName = "ak_test_1";
		String policyName = "allowUsername";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("ak_test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// username 符合条件
		String body = "Action=ListPolicies&Version=2010-05-08";
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		// username 不符合条件
		body = "Action=ListPolicies&Version=2010-05-08";
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(body, user3accessKey, user3secretKey);
		assertEquals(403, result3.first().intValue());
	}

	@Test
	/*
	 * d.符合userid匹配允许访问
	 */
	public void test_ListPolicies_Condition_userid_string() {
		String policyName = "allowUsername";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals", "ctyun:userid", Arrays.asList("test1abc")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		// userid 符合条件
		String body = "Action=ListPolicies&Version=2010-05-08";
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());
		// userid 不符合条件
		body = "Action=ListPolicies&Version=2010-05-08";
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(body, user2accessKey, user2secretKey);
		assertEquals(403, result3.first().intValue());

		// StringNotEquals
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEquals", "ctyun:userid", Arrays.asList("test1abc")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result.first().intValue());
		result = IAMTestUtils.invokeHttpsRequest(body, user2accessKey, user2secretKey);
		assertEquals(200, result.first().intValue());

		// StringEqualsIgnoreCase
		conditions.clear();
		conditions
				.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase", "ctyun:userid", Arrays.asList("test1abc")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());
		result = IAMTestUtils.invokeHttpsRequest(body, user2accessKey, user2secretKey);
		assertEquals(200, result.first().intValue());

		// StringNotEqualsIgnoreCase
		conditions.clear();
		conditions.add(
				IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase", "ctyun:userid", Arrays.asList("test1abc")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result.first().intValue());
		result = IAMTestUtils.invokeHttpsRequest(body, user2accessKey, user2secretKey);
		assertEquals(403, result.first().intValue());

		// StringLike
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:userid", Arrays.asList("test1*")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());
		result = IAMTestUtils.invokeHttpsRequest(body, user2accessKey, user2secretKey);
		assertEquals(403, result.first().intValue());

		//StringNotLike
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("StringNotLike", "ctyun:userid", Arrays.asList("test1*")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result.first().intValue());
		result = IAMTestUtils.invokeHttpsRequest(body, user2accessKey, user2secretKey);
		assertEquals(200, result.first().intValue());
	}

	@Test
	/*
	 * e.符合实际条件允许访问
	 */
	public void test_ListPolicies_Condition_CurrentTime() {
		String userName = "ak_test_1";
		String policyName = "allowDateGreate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2019-01-01T00:00:00Z")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 时间符合条件
		String body = "Action=ListPolicies&Version=2010-05-08";
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2050-01-01T00:00:00Z")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 时间不符合条件
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());
	}

	@Test
	/*
	 * f.设置不允许ssl访问
	 */
	public void test_ListPolicies_Condition_SecureTransport() {
		String userName = "ak_test_1";
		String policyName = "DenySSL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 允许ssl访问
		String body = "Action=ListPolicies&Version=2010-05-08";
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("false")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 不允许ssl访问
		body = "Action=ListPolicies&Version=2010-05-08";
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());

	}
	
	/**
	 * 一条策略包含多个condition
	 */
	@Test
	public void test_ListPolicies_More_Conditions() {
		String policyName = "moreConditions";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("true")));
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList("test_1")));
		conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:UserAgent",Arrays.asList("Java/1.5.0")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ListPolicies"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":policy/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		
		String body = "Action=ListPolicies&Version=2010-05-08";
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result2.first().intValue());
		result2 = IAMTestUtils.invokeHttpsRequest(body, user2accessKey, user2secretKey);
		assertEquals(403, result2.first().intValue());

	}
	
	@Test
	public void test1() {
		String policeName ="allowUsername";
//		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policeName, 200);
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
}
