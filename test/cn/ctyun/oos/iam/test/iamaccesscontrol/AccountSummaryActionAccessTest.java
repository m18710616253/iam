package cn.ctyun.oos.iam.test.iamaccesscontrol;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.apache.hadoop.hdfs.qjournal.protocol.QJournalProtocolProtos.NewEpochRequestProto;
import org.eclipse.jetty.util.UrlEncoded;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.input.SAXBuilder;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.oos.hbase.HBaseUtil;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.action.api.UserAction;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.param.CreateUserParam;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.time.TimeUtils;
import common.tuple.Pair;

public class AccountSummaryActionAccessTest {

	public static final String OOS_IAM_DOMAIN = "https://oos-cd-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName = "cd";

	private static String ownerName = "root_user@test.com";
	public static final String accessKey = "userak";
	public static final String secretKey = "usersk";

	public static final String user1Name = "test_1";
	public static final String user2Name = "test_2";
	public static final String user3Name = "Abc1";
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

//	@BeforeClass
	public static void setUpBeforeClass() throws Exception {

		IAMTestUtils.TrancateTable("oos-aksk-wtz");
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
	}

//	@Before
	@Test
	public void setUp() throws Exception {
//		IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
//		IAMTestUtils.TrancateTable(IAMTestUtils.iamGroupTable);
//		IAMTestUtils.TrancateTable(IAMTestUtils.iammfaDeviceTable);

		String groupName = mygroupName;
		IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name, 200);
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user2Name, 200);
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user3Name, 200);
	}
	
	@Test
	public void test_GetAccountSummary_noPolicy() throws JSONException {
		String user2xmlString = IAMInterfaceTestUtils.GetAccountSummary(user2accessKey, user2secretKey, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:GetAccountSummary on resource: arn:ctyun:iam::3rmoqzn03g6ga:*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}

	/*
	 * 1.allow Action=GetAccountSummary, resource=user/user1
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	/*
	 * 2.allow Action=GetAccountSummary, resource=user/*
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	@Test
	/*
	 * 3.allow Action=GetAccountSummary, resource=* 可以得到账户统计信息
	 */
	public void test_GetAccountSummary_Allow_Action_all2() throws JSONException {
		// 创建policy
		String policyName = "GetAccountSummaryPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey1, 200);

		String user2xmlString = IAMInterfaceTestUtils.GetAccountSummary(user2accessKey, user2secretKey, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:GetAccountSummary on resource: arn:ctyun:iam::3rmoqzn03g6ga:*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}
	
	@Test
	/*
	 * 3.allow Action=GetAccountSummary, resource=* 可以得到账户统计信息
	 */
	public void test_GetAccountSummary_Allow_Action_notMatch() throws JSONException {
		// 创建policy
		String policyName = "GetAccountSummaryPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey1, 403);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}
	

	@Test
	/*
	 * a.allow Action=GetAccountSummary, resource=user/* 资源和请求的action不匹配，policy不生效
	 */
	public void test_GetAccountSummary_Allow_Action_resourceNotMatch() throws JSONException {
		// 创建policy
		String policyName = "GetAccountSummaryPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String user1xmlString = IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetAccountSummary on resource: arn:ctyun:iam::3rmoqzn03g6ga:*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String user2xmlString = IAMInterfaceTestUtils.GetAccountSummary(user2accessKey, user2secretKey, 403);
		error = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:GetAccountSummary on resource: arn:ctyun:iam::3rmoqzn03g6ga:*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));
	}

	/*
	 * 4.allow NotAction=GetAccountSummary, resource=user/user1
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	/*
	 * 5.allow NotAction=GetAccountSummary, resource=user/*
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	@Test
	/*
	 * 6.allow NotAction=GetAccountSummary, resource=* 可匹配除了GetAccountSummary的所有其他操作
	 */
	public void test_GetAccountSummary_Allow_NotAction_all() throws JSONException {
		// 创建policy
		String policyName = "GetAccountSummaryPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		// 验证创建user1 user2都不允许得到账户信息
		String user1xmlString = IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetAccountSummary on resource: arn:ctyun:iam::3rmoqzn03g6ga:*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String user2xmlString = IAMInterfaceTestUtils.GetAccountSummary(user2accessKey, user2secretKey, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:GetAccountSummary on resource: arn:ctyun:iam::3rmoqzn03g6ga:*.",
				error1.get("Message"));
		assertEquals("/", error1.get("Resource"));

		// 验证除了create group所有方法都允許
//		List<String> excludes = new ArrayList<String>();
//		excludes.add("GetAccountSummary");
//
//		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
//		Pair<String, String> tag = new Pair<String, String>();
//		tag.first("key1");
//		tag.second("value1");
//		tags.add(tag);
//		String policyName2 = "GetAccountSummaryPolicy2";
//		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
//				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
//				null);

//		IAMInterfaceTestUtils.AllowActionResourceALL(accessKey, secretKey, excludes, user1accessKey1, user1secretKey1,
//				user2Name, tags, policyName2, policyString2, accountId, "group88", "mfa2");
	}

	/*
	 * 7.allow Action=GetAccountSummary, Notresource=user/user1
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	/*
	 * 8.allow Action=GetAccountSummary, Notresource=user/*
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	@Test
	/*
	 * 9.allow Action=GetAccountSummary, Notresource=* 允许GetAccountSummary 但是资源是非*
	 */
	public void test_GetAccountSummary_Allow_Action_NotResource() throws JSONException {
		// 创建policy
		String policyName = "GetAccountSummaryPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String user1xmlString = IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetAccountSummary on resource: arn:ctyun:iam::3rmoqzn03g6ga:*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String user2xmlString = IAMInterfaceTestUtils.GetAccountSummary(user2accessKey, user2secretKey, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:GetAccountSummary on resource: arn:ctyun:iam::3rmoqzn03g6ga:*.",
				error1.get("Message"));
		assertEquals("/", error1.get("Resource"));
	}

	/*
	 * 10.allow NotAction=GetAccountSummary, NotResource=user/user1
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	/*
	 * 11.allow NotAction=GetAccountSummary, NotResource=user/*
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	@Test
	/*
	 * 12.allow NotAction=GetAccountSummary, NotResource=* 允许非GetAccountSummary
	 * 但是资源是非*
	 */
	public void test_GetAccountSummary_Allow_NotAction_NotResource() throws JSONException {
		// 创建policy
		String policyName = "GetAccountSummaryPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("iam:GetAccountSummary"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 验证请求
		String user1xmlString = IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey1, 403);
		JSONObject error = IAMTestUtils.ParseErrorToJson(user1xmlString);
		assertEquals("AccessDenied", error.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user1Name
				+ " is not authorized to perform: iam:GetAccountSummary on resource: arn:ctyun:iam::3rmoqzn03g6ga:*.",
				error.get("Message"));
		assertEquals("/", error.get("Resource"));

		String user2xmlString = IAMInterfaceTestUtils.GetAccountSummary(user2accessKey, user2secretKey, 403);
		JSONObject error1 = IAMTestUtils.ParseErrorToJson(user2xmlString);
		assertEquals("AccessDenied", error1.get("Code"));
		assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/" + user2Name
				+ " is not authorized to perform: iam:GetAccountSummary on resource: arn:ctyun:iam::3rmoqzn03g6ga:*.",
				error1.get("Message"));
		assertEquals("/", error1.get("Resource"));

		List<Pair<String, String>> tags = new ArrayList<Pair<String, String>>();
		Pair<String, String> tag = new Pair<String, String>();
		tag.first("key1");
		tag.second("value1");
//		IAMInterfaceTestUtils.DenyActionResourceALL(accessKey, secretKey, user1accessKey1, user1secretKey1, "test_1",
//				tags, policyName, policyString, accountId, "group88", "mfa3");
	}

	/*
	 * 13.Deny Action=GetAccountSummary, resource=user/user1
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	/*
	 * 14.Deny Action=GetAccountSummary, resource=user/*
	 */

	@Test
	/*
	 * 15.Deny Action=GetAccountSummary, resource=*
	 */
	public void test_GetAccountSummary_Deny_Action_Resource() {
		// 创建policy
		String policyName = "DenyGetAccountSummaryPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 给用户添加policy
		String userName = "test_1";
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName, 200);

		// 显示拒绝
		IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey2, 403);

		String policyName2 = "AllowGetAccountSummaryPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// user1没有权限查看账户统计信息，user2可以
		IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey2, 403);
		IAMInterfaceTestUtils.GetAccountSummary(user2accessKey, user2secretKey, 200);
	}

	@Test
	/*
	 * b.Deny Action=GetAccountSummary, resource=user/* 资源不匹配，deny失败
	 */
	public void test_GetAccountSummary_Deny_Action_ReourceNotMatch() {
		// 创建policy
		String policyName = "DenyGetAccountSummaryPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 显示拒绝资源不匹配未生效
		IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey1, 403);

		String policyName2 = "AllowGetAccountSummaryPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝未生效，有显示允许，user1可以查看账户统计信息
		IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.GetAccountSummary(user2accessKey, user2secretKey, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	/*
	 * 16.Deny Action=GetAccountSummary, NotResource=user/user1
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	/*
	 * 17.Deny Action=GetAccountSummary, NotResource=user/*
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	@Test
	/*
	 * 18.Deny Action=GetAccountSummary, NotResource=*
	 */
	public void test_GetAccountSummary_Deny_Action_NotResouce() {
		// 创建policy
		String policyName = "DenyGetAccountSummaryPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 隐式拒绝
		IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey1, 403);

		String policyName2 = "AllowGetAccountSummaryPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 显示拒绝user1 user2失效
		IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.GetAccountSummary(user2accessKey, user2secretKey, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);

	}

	/*
	 * 19.Deny NotAction=GetAccountSummary, Resource=user/user1
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	/*
	 * 20.Deny NotAction=GetAccountSummary, Resource=user/*
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	@Test
	/*
	 * 21.Deny NotAction=GetAccountSummary, Resource=* 拒绝除GetAccountSummary以外的操作
	 */
	public void test_GetAccountSummary_Deny_NotAction_Resource() {
		// 创建policy
		String policyName = "DenyGetAccountSummaryPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 隐式拒绝
		IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey1, 403);

		String policyName2 = "AllowGetAccountSummaryPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 没有显示拒绝，允许user1 user2的GetAccountSummary操作
		IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.GetAccountSummary(user2accessKey, user2secretKey, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	/*
	 * 22.Deny NotAction=GetAccountSummary, NotResource=user/user1
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	/*
	 * 23.Deny NotAction=GetAccountSummary, NotResource=user/*
	 * GetAccountSummary的资源是*，该项测试用例没有意义
	 */

	@Test
	/*
	 * 24.Deny NotAction=GetAccountSummary, NotResource=*
	 * 拒绝除GetAccountSummary以外的操作（策略不起作用）
	 */
	public void test_GetAccountSummary_Deny_NotAction_NotResource() {
		// 创建policy
		String policyName = "DenyGetAccountSummaryPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("iam:GetAccountSummary"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 隐式拒绝
		IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey1, 403);

		String policyName2 = "AllowGetAccountSummaryPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		// 允许user1 user2的GetAccountSummary操作
		IAMInterfaceTestUtils.GetAccountSummary(user1accessKey1, user1secretKey1, 200);
		IAMInterfaceTestUtils.GetAccountSummary(user2accessKey, user2secretKey, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@Test
	/*
	 * c.在IP范围的允许访问
	 */
	public void test_GetAccountSummary_Condition_sourceIP() {
		String policyName = "allowspecialIP";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("192.168.1.1/24")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 在IP范围
		String body = "Action=GetAccountSummary&Version=2010-05-08";
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
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}

	@Test
	/*
	 * d.符合username匹配允许访问
	 */
	public void test_GetAccountSummary_Condition_username() {
		String policyName = "allowUsername";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);

		// username 符合条件
		String body = "Action=GetAccountSummary&Version=2010-05-08";
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		// username 不符合条件
		body = "Action=GetAccountSummary&Version=2010-05-08";
		Pair<Integer, String> result3 = IAMTestUtils.invokeHttpsRequest(body, user3accessKey, user3secretKey);
		assertEquals(403, result3.first().intValue());
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	/*
	 * e.符合实际条件允许访问
	 */
	public void test_GetAccountSummary_Condition_CurrentTime() {
		String policyName = "allowDateGreate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2019-01-01T00:00:00Z")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);

		// 时间符合条件
		String body = "Action=GetAccountSummary&Version=2010-05-08";
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2050-01-01T00:00:00Z")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 时间不符合条件
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	/*
	 * f. 设置不允许ssl访问
	 */
	public void test_GetAccountSummary_Condition_SecureTransport() {
		String policyName = "DenySSL";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);

		// 允许ssl访问
		String body = "Action=GetAccountSummary&Version=2010-05-08";
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("false")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		// 不允许ssl访问
		body = "Action=GetAccountSummary&Version=2010-05-08";
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(403, result2.first().intValue());
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);

	}
	
	@Test
	public void test_GetAccountSummary_condition_SecureTransport2() {
		String policyName = "allowDateGreate";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2019-01-01T00:00:00Z")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);

		// 时间符合条件
		String body = "Action=GetAccountSummary&Version=2010-05-08";
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result.first().intValue());

		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime",
				Arrays.asList("2050-01-01T00:00:00Z")));
		policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:GetAccountSummary"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"),
				conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 时间不符合条件
		Pair<Integer, String> result2 = IAMTestUtils.invokeHttpsRequest(body, user1accessKey1, user1secretKey1);
		assertEquals(200, result2.first().intValue());
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, mygroupName, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

}
