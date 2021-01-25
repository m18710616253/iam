package cn.ctyun.oos.iam.test.iamaccesscontrol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.ctyun.common.Consts;
import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.hbase.HBaseUserToTag;
import cn.ctyun.oos.hbase.HBaseVSNTag;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.action.api.PolicyAction;
import cn.ctyun.oos.iam.server.action.api.UserAction;
import cn.ctyun.oos.iam.server.entity.AccountPasswordPolicy;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.param.CreatePolicyParam;
import cn.ctyun.oos.iam.server.param.CreateUserParam;
import cn.ctyun.oos.iam.server.param.UserPolicyParam;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.metadata.UserToTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta.VSNTagType;
import common.tuple.Pair;

/**
 * 测试IAMAccoutPasswordPolicy的权限
 * 有效操作为GetAccountPasswordPolicy，UpdateAccountPasswordPolicy，DeleteAccountPasswordPolicy；
 * 对应的有效resource为*（仅）
 */

public class AccountPasswordPolicyActionAccessTest {
	public String http = "https";
	public String signVersion = "PreV4";

	public static final String OOS_IAM_DOMAIN = "https://oos-xl-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName = "loc6";

	private static String ownerName = "test01@ctyun.cn";
	public static final String accessKey = "65dd530d67f7f88e222f";
	public static final String secretKey = "bee6a1d024e999bdf72e04d6a37d85bba789c5d3";

	public static final String user1Name = "test01_subUser01";
	public static final String user2Name = "test01_subUser02";
	public static final String user3Name = "test01_subUser03";
	public static final String user1accessKey1 = "8ff34a2d9a860648833d";
	public static final String user1secretKey1 = "c025573a77079a278aea03cf4233eeffefac783a";
//	public static final String user1accessKey2 = "1234567890123456";
//	public static final String user1secretKey2 = "user1secretKey2lllll";
	public static final String user2accessKey = "74dbcc660b2fffae8956";
	public static final String user2secretKey = "3123091d5e5967307e6a2791c29f443af368e806";
	public static final String user3accessKey = "6acbe6f3174e3fbddd17";
	public static final String user3secretKey = "2a39fc0f09f958e4d74239101db00578cf537621";

	public static String accountId = "0000000gc0uy9";
	public static String mygroupName = "mygroup";

	public static OwnerMeta owner = new OwnerMeta(ownerName);
	public static MetaClient metaClient = MetaClient.getGlobalClient();
	static Configuration globalConf = GlobalHHZConfig.getConfig();
	
	
	@Before
	public void before() throws Exception {
		User user=new User();
		user.accountId=accountId;
		user.userName=user1Name;
		user=HBaseUtils.get(user);
		if(user.password!=null)
			IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);
		
		user.accountId=accountId;
		user.userName=user2Name;
		user=HBaseUtils.get(user);
		if(user.password!=null)
			IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user2Name, 200);
		
		user.accountId=accountId;
		user.userName=user3Name;
		user=HBaseUtils.get(user);
		if(user.password!=null)
			IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user3Name, 200);

	}

	/**
	 * 设置为allow策略，策略为允许accountpasswordpolicy 与策略匹配
	 **/
	@Test
	public void test_AccountPasswordPolicy_allow_match() throws Exception {
		String policyName = "createPolicyfortestaccountpassword";
		createPolicy(Effect.Allow, policyName, "Action",
				Arrays.asList("iam:UpdateAccountPasswordPolicy", "iam:GetAccountPasswordPolicy","iam:DeleteAccountPasswordPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), null);
		String policyArn = "arn:ctyun:iam::" + accountId + ":policy/" + policyName;
		attachPolicyToUser(user1Name, policyArn);

		String getresult = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
		System.out.println("PasswordPolicy=" + getresult);
		String updateresult = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
		String deleteresult = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	// 设置conditions
	@Test
	public void test_AccountPasswordPolicy_allow_match_condition() throws Exception {
		String policyName = "createPolicyfortestaccountpassword";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));

		createPolicy(Effect.Allow, policyName, "Action",
				Arrays.asList("iam:UpdateAccountPasswordPolicy", "iam:GetAccountPasswordPolicy",
						"iam:DeleteAccountPasswordPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		String policyArn = "arn:ctyun:iam::0000000gc0uy9:policy/" + policyName;
		attachPolicyToUser(user1Name, policyArn);

		String updateresult = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
		String getresult = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
		System.out.println(getresult);
		String deleteresult = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	// 设置resource为user/*（account password policy允许的资源为*）
	@Test
	public void test_AccountPasswordPolicy_allow_match_resource_invalid() throws Exception {
		String policyName = "createPolicyfortestaccountpassword";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		// 设置resource为user/*
		createPolicy(Effect.Allow, policyName, "Action",
				Arrays.asList("iam:UpdateAccountPasswordPolicy", "iam:GetAccountPasswordPolicy",
						"iam:DeleteAccountPasswordPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"), conditions);
		String policyArn = "arn:ctyun:iam::0000000gc0uy9:policy/" + policyName;
		attachPolicyToUser(user1Name, policyArn);

		String updateresult = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String getresult = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		System.out.println(getresult);
		String deleteresult = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/***
	 * allow策略，NotAction
	 ***/
	@Test
	public void test_AccountPasswordPolicy_allow_match_notAction() throws Exception {
		String policyName = "createPolicyfortestaccountpassword";
		createPolicy(Effect.Allow, policyName, "NotAction", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"), null);
		String policyArn = "arn:ctyun:iam::0000000gc0uy9:policy/" + policyName;
		attachPolicyToUser(user1Name, policyArn);

		String updateresult = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
		String getresult = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
		String deleteresult = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/***
	 * allow策略，NotAction
	 ***/
	@Test
	public void test_AccountPasswordPolicy_allow_match_notAction2() throws Exception {
		String policyName = "createPolicyfortestaccountpassword";
		createPolicy(Effect.Allow, policyName, "NotAction", Arrays.asList("iam:GetAccountPasswordPolicy"), "Resource",
				Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"), null);
		String policyArn = "arn:ctyun:iam::0000000gc0uy9:policy/" + policyName;
		attachPolicyToUser(user1Name, policyArn);

		String updateresult = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
		String getresult = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/***
	 * allow策略，NotResource
	 ***/
	@Test
	public void test_AccountPasswordPolicy_allow_match_notResource() throws Exception {
		String policyName = "createPolicyfortestaccountpassword";
		createPolicy(Effect.Allow, policyName, "Action",
				Arrays.asList("iam:UpdateAccountPasswordPolicy", "iam:GetAccountPasswordPolicy",
						"iam:DeleteAccountPasswordPolicy"),
				"NotResource", Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/" + user1Name), null);
		String policyArn = "arn:ctyun:iam::0000000gc0uy9:policy/" + policyName;
		attachPolicyToUser(user1Name, policyArn);

		String updateresult = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
		String getresult = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
		String deleteresult = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/***
	 * allow策略，NotResource
	 ***/
	@Test
	public void test_AccountPasswordPolicy_allow_match_notResource2() throws Exception {
		String policyName = "createPolicyfortestaccountpassword";
		createPolicy(Effect.Allow, policyName, "Action",
				Arrays.asList("iam:UpdateAccountPasswordPolicy", "iam:GetAccountPasswordPolicy",
						"iam:DeleteAccountPasswordPolicy"),
				"NotResource", Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"), null);
		String policyArn = "arn:ctyun:iam::0000000gc0uy9:policy/" + policyName;
		attachPolicyToUser(user1Name, policyArn);

		// 隐式拒绝
		String updateresult = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String getresult = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/***
	 * allow策略，NotAction,NotResource
	 ***/
	@Test
	public void test_AccountPasswordPolicy_allow_match_notActionNotResource() throws Exception {
		String policyName = "createPolicyfortestaccountpassword";
		createPolicy(Effect.Allow, policyName, "NotAction", Arrays.asList("iam:GetUser"), "NotResource",
				Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/" + user1Name), null);
		String policyArn = "arn:ctyun:iam::0000000gc0uy9:policy/" + policyName;
		attachPolicyToUser(user1Name, policyArn);

		String updateresult = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
		String getresult = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
		String deleteresult = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/***
	 * allow策略，NotAction,NotResource
	 ***/
	@Test
	public void test_AccountPasswordPolicy_allow_match_notActionNotResource2() throws Exception {
		String policyName = "createPolicyfortestaccountpassword";
		createPolicy(Effect.Allow, policyName, "NotAction", Arrays.asList("iam:GetAccountPasswordPolicy"),
				"NotResource", Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/" + user1Name), null);
		String policyArn = "arn:ctyun:iam::0000000gc0uy9:policy/" + policyName;
		attachPolicyToUser(user1Name, policyArn);

		String updateresult = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);
		String getresult = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/*
	 * allow策略，与策略不匹配 无其他策略，隐式拒绝
	 **/
	@Test
	public void test_AccountPasswordPolicy_allow_notMatch() throws Exception {
		String policyName = "createPolicyfortestaccountpassword";
		String policyArn = "arn:ctyun:iam::0000000gc0uy9:policy/" + policyName;
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("TEST01*")));

		// 与condition不匹配，无其他策略，隐式拒绝
		createPolicy(Effect.Allow, policyName, "Action",
				Arrays.asList("iam:UpdateAccountPasswordPolicy", "iam:GetAccountPasswordPolicy",
						"iam:DeleteAccountPasswordPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"), conditions);
		attachPolicyToUser(user1Name, policyArn);

		String updateresult = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String getresult = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);

		// 与NotAction匹配,隐式拒绝
		createPolicy(Effect.Allow, policyName, "NotAction",
				Arrays.asList("iam:UpdateAccountPasswordPolicy", "iam:GetAccountPasswordPolicy",
						"iam:DeleteAccountPasswordPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"), null);
		String updateresult2 = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String getresult2 = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult2 = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);

		// 与Resource不匹配，隐式拒绝
		createPolicy(Effect.Allow, policyName, "Action",
				Arrays.asList("iam:UpdateAccountPasswordPolicy", "iam:GetAccountPasswordPolicy",
						"iam:DeleteAccountPasswordPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"), null);
		String updateresult3 = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String getresult3 = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult3 = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/**
	 * 策略为deny； deny优先级最高，与deny策略匹配时，有无其他allow策略，均显示拒绝；
	 * 与deny策略不匹配时，验证其他策略，若存在allow策略，允许访问且匹配，则允许
	 **/
	@Test
	public void test_AccountPasswordPolicy_deny_match() throws Exception {
		String policyName = "createPolicyfortestaccountpassword";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));

		createPolicy(Effect.Deny, policyName, "Action",
				Arrays.asList("iam:UpdateAccountPasswordPolicy", "iam:GetAccountPasswordPolicy",
						"iam:DeleteAccountPasswordPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"), conditions);
		String policyArn = "arn:ctyun:iam::0000000gc0uy9:policy/" + policyName;
		attachPolicyToUser(user1Name, policyArn);

		// 显示拒绝
		String updateresult = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String getresult = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);

		// 新建allow策略
		String policyName2 = "createallowpolicy";
		createPolicy(Effect.Allow, policyName2, "Action",
				Arrays.asList("iam:UpdateAccountPasswordPolicy", "iam:GetAccountPasswordPolicy",
						"iam:DeleteAccountPasswordPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		String groupName = "creategroupfortestperssion";
		IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user2Name, 200);

		String updateresult2 = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user2accessKey, user2secretKey, 403);
		String getresult2 = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user2accessKey, user2secretKey, 403);
		String deleteresult2 = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user2accessKey, user2secretKey, 403);

		// 修改deny策略，NotAction
		createPolicy(Effect.Deny, policyName, "NotAction", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"), conditions);
		String updateresult3 = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String getresult3 = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult3 = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);

		// 修改deny策略，NotResource
		createPolicy(Effect.Deny, policyName, "Action",
				Arrays.asList("iam:UpdateAccountPasswordPolicy", "iam:GetAccountPasswordPolicy",
						"iam:DeleteAccountPasswordPolicy"),
				"NotResource", Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"), conditions);
		String updateresult4 = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String getresult4 = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult4 = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, user2Name, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);
	}

	/**
	 * 策略为deny； deny优先级最高，与deny策略匹配时，有无其他allow策略，均显示拒绝； 与deny策略不匹配时，无其他策略为隐式拒绝；
	 * 有其他策略，验证其他策略，若存在allow策略，允许访问且匹配，则允许
	 **/
	@Test
	public void test_AccountPasswordPolicy_deny_notMatch() throws Exception {
		String policyName = "createPolicyfortestaccountpassword";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));

		createPolicy(Effect.Deny, policyName, "Action", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"), conditions);
		String policyArn = "arn:ctyun:iam::0000000gc0uy9:policy/" + policyName;
		attachPolicyToUser(user1Name, policyArn);

		// 隐式拒绝
		String updateresult = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String getresult = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);

		// 新建allow策略，添加到group
		String policyName2 = "createallowpolicy";
		createPolicy(Effect.Allow, policyName2, "Action",
				Arrays.asList("iam:UpdateAccountPasswordPolicy", "iam:GetAccountPasswordPolicy",
						"iam:DeleteAccountPasswordPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"), conditions);
		String groupName = "creategroupfortestperssion";
		IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user2Name, 200);

		String updateresult2 = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user2accessKey, user2secretKey, 200);
		String getresult2 = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user2accessKey, user2secretKey, 200);
		String deleteresult2 = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user2accessKey, user2secretKey, 200);

		// 修改deny策略，与conditions不匹配
		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("TEST01*")));
		createPolicy(Effect.Deny, policyName, "Action",
				Arrays.asList("iam:UpdateAccountPasswordPolicy", "iam:GetAccountPasswordPolicy",
						"iam:DeleteAccountPasswordPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"), conditions2);
		String updateresult3 = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String getresult3 = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult3 = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);

		String updateresult4 = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user2accessKey, user2secretKey, 200);
		String getresult4 = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user2accessKey, user2secretKey, 200);
		String deleteresult4 = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user2accessKey, user2secretKey, 200);

		// 修改deny策略，与Action不匹配
		createPolicy(Effect.Deny, policyName, "Action", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::0000000gc0uy9:*"), conditions);
		String updateresult5 = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String getresult5 = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult5 = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);

		String updateresult6 = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user2accessKey, user2secretKey, 200);
		String getresult6 = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user2accessKey, user2secretKey, 200);
		String deleteresult6 = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user2accessKey, user2secretKey, 200);

		// 修改deny策略，与resource不匹配
		createPolicy(Effect.Deny, policyName, "Action",
				Arrays.asList("iam:UpdateAccountPasswordPolicy", "iam:GetAccountPasswordPolicy",
						"iam:DeleteAccountPasswordPolicy"),
				"Resource", Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"), conditions);
		String updateresult7 = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String getresult7 = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult7 = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);

		String updateresult8 = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user2accessKey, user2secretKey, 200);
		String getresult8 = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user2accessKey, user2secretKey, 200);
		String deleteresult8 = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user2accessKey, user2secretKey, 200);

		// 修改allow策略，与allow策略不匹配
		String policyName1 = "createpolicyfornotmatch";
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::0000000gc0uy9:user/*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		String updateresult9 = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String getresult9 = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult9 = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, user2Name, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DeleteGroup(accessKey, secretKey, groupName, 200);
	}

	/**
	 * 无策略，拒绝
	 **/
	@Test
	public void test_AccountPasswordPolicy_nopolicy() throws Exception {
		String updateresult = IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String getresult = IAMInterfaceTestUtils.GetAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);
		String deleteresult = IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(user1accessKey1, user1secretKey1, 403);

	}
	
	
	/**
	 * 测试condition
	 * @throws Exception 
	 */
	@Test
	public void test_changePassword_condition_StringEquals() throws Exception {
		// accountpasswdpolicy 不允许修改密码
		Pair<String, Boolean> passwdsetdefault = new Pair<>();
		passwdsetdefault.first("AllowUsersToChangePassword");
		passwdsetdefault.second(false);
		//更新密码策略：不允许用户自己修改密码
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdsetdefault);
		create(accessKey, secretKey, user2Name, "accountpasswordpolicy", null, passwdsetdefault);
		// 创建用户密码
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		create(accessKey, secretKey, user2Name, "createpassword", null, null);
		String oldPassword = "password123";
		String newPassword = "newpassword123";
		String policyName = "createpolicyfortestcondition";
		
		//StringEquals，密码策略优先级最高
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals", "ctyun:username", Arrays.asList("test01_subUser01")));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		String result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		result = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, oldPassword,
				newPassword, 403);
		
		
		//StringNotEquals
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEquals", "ctyun:username", Arrays.asList("test01_subUser01")));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);
		result = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, oldPassword,
				newPassword, 200);
		
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user2Name, 200);
	}
	

	@Test
	public void test_changePassword_condition_StringEqualsIgnoreCase() throws Exception {
		// accountpasswdpolicy 不允许修改密码
		Pair<String, Boolean> passwdsetdefault = new Pair<>();
		passwdsetdefault.first("AllowUsersToChangePassword");
		passwdsetdefault.second(false);
		//更新密码策略：不允许用户自己修改密码
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdsetdefault);
		create(accessKey, secretKey, user2Name, "accountpasswordpolicy", null, passwdsetdefault);
		// 创建用户密码
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		create(accessKey, secretKey, user2Name, "createpassword", null, null);
		String oldPassword = "password123";
		String newPassword = "newpassword123";
		String policyName = "createpolicyfortestcondition";
		
		//StringEqualsIgnoreCase
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase", "ctyun:username", Arrays.asList("Test01_subUser01")));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		String result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		result = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, oldPassword,
				newPassword, 403);
		
		//StringNotEqualsIgnoreCase
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase", "ctyun:username", Arrays.asList("Test01_subUser01")));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);
		result = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, oldPassword,
				newPassword, 200);
		
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user2Name, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}
	
	@Test
	public void test_changePassword_condition_StringLike() throws Exception {
		// accountpasswdpolicy 不允许修改密码
		Pair<String, Boolean> passwdsetdefault = new Pair<>();
		passwdsetdefault.first("AllowUsersToChangePassword");
		passwdsetdefault.second(false);
		//更新密码策略：不允许用户自己修改密码
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdsetdefault);
		create(accessKey, secretKey, user2Name, "accountpasswordpolicy", null, passwdsetdefault);
		// 创建用户密码
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		create(accessKey, secretKey, user2Name, "createpassword", null, null);
		String oldPassword = "password123";
		String newPassword = "newpassword123";
		String policyName = "createpolicyfortestcondition";
		
		//StringLike
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:UserAgent", Arrays.asList("Java/1.6.0")));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		String result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);
		result = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, oldPassword,
				newPassword, 403);
		
		//StringNotLike
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("StringNotLike", "ctyun:userid", Arrays.asList("test01*")));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		result = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, oldPassword,
				newPassword, 200);
		
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user2Name, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}
	
	@Test
	public void test_changePassword_condition_DateEquals() throws Exception {
		// accountpasswdpolicy 不允许修改密码
		Pair<String, Boolean> passwdsetdefault = new Pair<>();
		passwdsetdefault.first("AllowUsersToChangePassword");
		passwdsetdefault.second(false);
		//更新密码策略：不允许用户自己修改密码
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdsetdefault);
		create(accessKey, secretKey, user2Name, "accountpasswordpolicy", null, passwdsetdefault);
		// 创建用户密码
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		create(accessKey, secretKey, user2Name, "createpassword", null, null);
		String oldPassword = "password123";
		String newPassword = "newpassword123";
		String policyName = "createpolicyfortestcondition";
		
		//DateEquals
		String yesterdayString=OneDay0UTCTimeString(-1);
	    String todyString=OneDay0UTCTimeString(0);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateEquals","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		String result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);
		
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("DateEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		
		//DateNotEquals
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("DateNotEquals","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		result = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, oldPassword,
				newPassword, 200);
		
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("DateEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		result = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, oldPassword,
				newPassword, 403);
		
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user2Name, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}
	
	@Test
	public void test_changePassword_condition_DateLessThan() throws Exception {
		// accountpasswdpolicy 不允许修改密码
		Pair<String, Boolean> passwdsetdefault = new Pair<>();
		passwdsetdefault.first("AllowUsersToChangePassword");
		passwdsetdefault.second(false);
		//更新密码策略：不允许用户自己修改密码
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdsetdefault);
		create(accessKey, secretKey, user2Name, "accountpasswordpolicy", null, passwdsetdefault);
		// 创建用户密码
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		create(accessKey, secretKey, user2Name, "createpassword", null, null);
		String oldPassword = "password123";
		String newPassword = "newpassword123";
		String policyName = "createpolicyfortestcondition";
		
		//DateEquals
		String yesterdayString=OneDay0UTCTimeString(-1);
	    String todyString=OneDay0UTCTimeString(0);
	    String tomorrowString=OneDay0UTCTimeString(1);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		String result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);
		
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList(todyString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);
		
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList(tomorrowString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		
		//DateLessThanEquals
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("DateLessThanEquals","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		result = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, oldPassword,
				newPassword, 403);
		
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("DateLessThanEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		result = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, oldPassword,
				newPassword, 403);
		
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("DateLessThanEquals","ctyun:CurrentTime",Arrays.asList(tomorrowString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		result = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, oldPassword,
				newPassword, 200);
		
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user2Name, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}
	
	@Test
	public void test_changePassword_condition_DateGreaterThan() throws Exception {
		// accountpasswdpolicy 不允许修改密码
		Pair<String, Boolean> passwdsetdefault = new Pair<>();
		passwdsetdefault.first("AllowUsersToChangePassword");
		passwdsetdefault.second(false);
		//更新密码策略：不允许用户自己修改密码
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdsetdefault);
		create(accessKey, secretKey, user2Name, "accountpasswordpolicy", null, passwdsetdefault);
		// 创建用户密码
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		create(accessKey, secretKey, user2Name, "createpassword", null, null);
		String oldPassword = "password123";
		String newPassword = "newpassword123";
		String policyName = "createpolicyfortestcondition";
		
		//DateEquals
		String yesterdayString=OneDay0UTCTimeString(-1);
	    String todyString=OneDay0UTCTimeString(0);
	    String tomorrowString=OneDay0UTCTimeString(1);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		String result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList(todyString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, newPassword,
				oldPassword, 200);
		
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList(tomorrowString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);
		
		//DateGreaterThanEquals
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThanEquals","ctyun:CurrentTime",Arrays.asList(yesterdayString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		result = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, oldPassword,
				newPassword, 200);
		
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThanEquals","ctyun:CurrentTime",Arrays.asList(todyString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		result = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, newPassword,
				oldPassword, 200);
		
		conditions.clear();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThanEquals","ctyun:CurrentTime",Arrays.asList(tomorrowString)));
		createPolicy(Effect.Allow, policyName, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		result = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, oldPassword,
				newPassword, 403);
		
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user2Name, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}
	
	/**
	 * 一个策略，两个statement
	 * @throws Exception
	 */
	@Test
	public void test_changePassword_twoStat() throws Exception {
		Pair<String, Boolean> passwdsetdefault = new Pair<>();
		passwdsetdefault.first("AllowUsersToChangePassword");
		passwdsetdefault.second(false);
		//更新密码策略：不允许用户自己修改密码
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdsetdefault);
		create(accessKey, secretKey, user2Name, "accountpasswordpolicy", null, passwdsetdefault);

		// 创建用户密码
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		create(accessKey, secretKey, user2Name, "createpassword", null, null);
		String oldPassword = "password123";
		String newPassword = "newpasswd123";
		
		String policyName = "changePassword_twoStat";
		List<Statement> statements = new ArrayList<Statement>();
		Statement s1 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "Action",
				Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
		statements.add(s1);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		Statement s2 = IAMTestUtils.CreateStatement(Effect.Deny, null, null, "Action", Arrays.asList("iam:ChangePassword"),
				"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user1Name), null);
		statements.add(s2);
		String policyString = IAMTestUtils.CreateMoreStatement(statements);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		
		String result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);
		String result2 = IAMInterfaceTestUtils.ChangePassword(user2accessKey, user2secretKey, user2Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user2Name, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}

	/**
	 * allow策略，策略允许，与策略匹配 不论AccountPasswordPolicy的设置，均可修改密码
	 **/
	@Test
	public void test_changPassword_allow_match() throws Exception {
		// accountpasswdpolicy 允许修改密码
		Pair<String, Boolean> passwdsetdefault = new Pair<>();
		passwdsetdefault.first("AllowUsersToChangePassword");
		passwdsetdefault.second(true);
		//更新密码策略：允许用户自己修改密码
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdsetdefault);

		// 创建用户密码
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String oldPassword = "password123";
		String newPassword = "newpasswd123";
		String policyName1 = "createpolicyfortestpassword";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));

		// resource为user/*
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		String result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，resource为user/userName
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user1Name), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result2 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，resource为*
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result3 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，NotAction
		createPolicy(Effect.Allow, policyName1, "NotAction", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result4 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，NotResource
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user3Name), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result5 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，NotAction，NotResource
		createPolicy(Effect.Allow, policyName1, "NotAction", Arrays.asList("iam:GetUser"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result6 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);//因为passwordPolicy是允许修改密码
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改passwordPolicy，为不允许修改密码
		Pair<String, Boolean> passwdset = new Pair<>();
		passwdset.first("AllowUsersToChangePassword");
		passwdset.second(false);
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdset);

		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result7 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，resource为user/userName
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user1Name), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result8 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，resource为*
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user1Name), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result9 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，NotAction
		createPolicy(Effect.Allow, policyName1, "NotAction", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result10 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，NotResource
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user3Name), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result11 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，NotAction，NotResource
		createPolicy(Effect.Allow, policyName1, "NotAction", Arrays.asList("iam:GetUser"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user3Name), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result12 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);

	}

	/**
	 * 策略为allow，无其他策略，与allow策略不匹配，为隐式拒绝，隐式拒绝需判断passwordpolicy
	 * 如果passwordpolicy允许修改密码,不为隐式拒绝，passwordpolicy允许修改密码则为允许；
	 * 若passwordpolicy不允许修改密码，判断policyLogin和过期且HardExpiry，最终结果为访问拒绝
	 */
	@Test
	public void test_changPassword_allow_notmatch() throws Exception {
		// passwordpolicy为允许修改密码
		Pair<String, Boolean> passwdsetdefault = new Pair<>();
		passwdsetdefault.first("AllowUsersToChangePassword");
		passwdsetdefault.second(true);
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdsetdefault);

		String oldPassword = "password123";
		String newPassword = "newpasswd123";
		String policyName1 = "createpolicyfortestpassword";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));

		// resource为user/user2Name，不匹配
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user2Name), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，conditions不匹配
		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("TeST01*")));
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions2);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result3 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与action不匹配
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result4 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与action匹配但为NotAction
		createPolicy(Effect.Allow, policyName1, "NotAction", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result5 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与resource匹配，但为NotResource
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result6 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改passwordpolicy为不允许修改密码
		Pair<String, Boolean> passwdset = new Pair<>();
		passwdset.first("AllowUsersToChangePassword");
		passwdset.second(false);
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdset);

		// resource为user/user2Name
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user2Name), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result7 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，NotResource
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		String result8 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，conditions不匹配
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions2);
		String result9 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，与action不匹配
		createPolicy(Effect.Allow, policyName1, "Action", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		String result10 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，NotAction
		createPolicy(Effect.Allow, policyName1, "NotAction", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		String result11 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);

	}

	/*
	 * 与deny策略匹配,访问控制为deny，访问控制权限高于passwordpolicy
	 **/
	@Test
	public void test_changePassword_deny_match() throws Exception {
		// accountpasswdpolicy 允许修改密码
		Pair<String, Boolean> passwdsetdefault = new Pair<>();
		passwdsetdefault.first("AllowUsersToChangePassword");
		passwdsetdefault.second(true);
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdsetdefault);

		// 创建用户密码
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String oldPassword = "password123";
		String newPassword = "newpasswd123";
		String policyName1 = "createpolicyfortestpassword";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));

		// resource为user/*
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		String result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，resource为user/userName
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user1Name), conditions);
		String result2 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，resource为*
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		String result3 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，NotAction
		createPolicy(Effect.Deny, policyName1, "NotAction", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		String result4 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，NotResource
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user3Name), conditions);
		String result5 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，NotAction，NotResource,
		createPolicy(Effect.Deny, policyName1, "NotAction", Arrays.asList("iam:GetUser"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user3Name), conditions);
		String result6 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改passwordPolicy，为不允许修改密码
		Pair<String, Boolean> passwdset = new Pair<>();
		passwdset.first("AllowUsersToChangePassword");
		passwdset.second(false);
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdset);

		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		String result7 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，resource为user/userName
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user1Name), conditions);
		String result8 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，resource为*
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user1Name), conditions);
		String result9 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，NotAction
		createPolicy(Effect.Deny, policyName1, "NotAction", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		String result10 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，NotResource
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user3Name), conditions);
		String result11 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，NotAction，NotResource
		createPolicy(Effect.Deny, policyName1, "NotAction", Arrays.asList("iam:GetUser"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user3Name), conditions);
		String result12 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);

	}

	/**
	 * deny策略不匹配，不存在其他策略，隐式拒绝，在隐式拒绝的时候，需要判断账户设置的passwordpolicy是否允许
	 * deny策略不匹配，存在allow策略，对allow策略进行验证
	 * allow策略允许，则且与allow策略匹配，则允许访问，不论passwordpolicy的设置
	 * allow策略不允许changepawd，则为隐式拒绝，同样判断passwordpolicy
	 */

	@Test
	public void test_changPassword_deny_notmatch() throws Exception {
		// passwordpolicy为允许修改密码
		Pair<String, Boolean> passwdsetdefault = new Pair<>();
		passwdsetdefault.first("AllowUsersToChangePassword");
		passwdsetdefault.second(true);
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdsetdefault);

		String oldPassword = "password123";
		String newPassword = "newpasswd123";
		String policyName1 = "createpolicyfortestpassword";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		// 创建密码
		create(accessKey, secretKey, user1Name, "createpassword", null, null);

		// resource为user/user2Name，不匹配
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user2Name), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		String result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，conditions不匹配
		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("TeST01*")));
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions2);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result2 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与action不匹配
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result3 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与action匹配但为NotAction
		createPolicy(Effect.Deny, policyName1, "NotAction", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result4 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与resource匹配，但为NotResource
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result5 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 添加allow策略，allow策略并未允许changpassword，隐式拒绝
		String policyName2 = "createfornoallowpolicy";
		createPolicy(Effect.Allow, policyName2, "Action", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user2Name), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		// resource为user/user2Name，不匹配
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user2Name), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result6 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);
		// 修改策略，conditions不匹配
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions2);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result7 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与action不匹配
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result8 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与action匹配但为NotAction
		createPolicy(Effect.Deny, policyName1, "NotAction", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result9 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与resource匹配，但为NotResource
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result10 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 添加allow策略，策略为允许changepassword，与allow策略匹配
		String policyName3 = "createforallowpolicy";
		createPolicy(Effect.Allow, policyName3, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName3, 200);

		// resource为user/user2Name，不匹配，但是因有匹配的allow策略，则允许
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user2Name), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result11 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，conditions不匹配
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions2);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result12 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与action不匹配
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result13 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与action匹配但为NotAction
		createPolicy(Effect.Deny, policyName1, "NotAction", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result14 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与resource匹配，但为NotResource
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result15 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);
		// 移除allow策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName3, 200);

		// 修改passwordpolicy为不允许修改密码
		Pair<String, Boolean> passwdset = new Pair<>();
		passwdset.first("AllowUsersToChangePassword");
		passwdset.second(false);
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwdset);

		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		// resource为user/user2Name
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user2Name), conditions);
		String result17 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，NotResource
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		String result18 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，conditions不匹配
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions2);
		String result19 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，与action不匹配
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		String result20 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，NotAction
		createPolicy(Effect.Deny, policyName1, "NotAction", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		String result21 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 添加allow策略，策略未允许changepassword
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

		// resource为user/user2Name
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user2Name), conditions);
		String result22 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，NotResource
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		String result23 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，conditions不匹配
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions2);
		String result24 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，与action不匹配
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		String result25 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 修改策略，NotAction
		createPolicy(Effect.Deny, policyName1, "NotAction", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		String result26 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		// 添加allow策略，策略允许changepassword
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName3, 200);

		// resource为user/user2Name，不匹配，但是因有匹配的allow策略，则允许
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user2Name), conditions);
		String result27 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，conditions不匹配
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions2);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result28 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与action不匹配
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:GetUser"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result29 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与action匹配但为NotAction
		createPolicy(Effect.Deny, policyName1, "NotAction", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result30 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 修改策略，与resource匹配，但为NotResource
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "NotResource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String result31 = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName3, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName3, 200);

	}

	/**
	 * 与deny，allow策略均不匹配，验证是否拒绝访问, 密码策略为空时，获取默认密码策略，允许访问
	 */
	@Test
	public void test_changPassword_notmatch_nopasswordpolicy() throws Exception {
		// 无passwordpolicy
		// 创建密码
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String oldPassword = "password123";
		String newPassword = "newpasswd123";
		String policyName1 = "createdenypolicy";
		String policyName2 = "createallowpolicy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("TEST01*")));
		// deny策略不匹配
		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user2Name), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		// allow策略,不匹配
		createPolicy(Effect.Allow, policyName2, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/" + user2Name), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		
		String result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 200);

		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);

	}

	/**
	 * changepassword为deny UpdateLoginProfile允许重置密码 不可以改密码
	 */
	@Test
	public void test_changePassword_deny() throws Exception {
		// 创建密码
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		String oldPassword = "password123";
		String newPassword = "newpasswd123";
		String policyName1 = "createpolicyfortestpassword";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));

		createPolicy(Effect.Deny, policyName1, "Action", Arrays.asList("iam:ChangePassword"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		String result = IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword,
				newPassword, 403);

		String result2 = IAMInterfaceTestUtils.UpdateLoginProfile(accessKey, secretKey, user1Name, newPassword, 200);

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

	}

	/**
	 * 使用账户创建，未添加策略，passwordpolicy为默认值，则允许修改
	 **/
	@Test
	public void test_changePassword_noPolicy() throws Exception {
		String oldPassword = "password123";
		String newPassword = "newpasswd123";
		IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(accessKey, secretKey, 200);
		// 创建密码，passwordpolicy默认为允许所有用户修改密码
		IAMInterfaceTestUtils.CreateLoginProfile(accessKey, secretKey, user1Name, "password123", 200);
		IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword, newPassword,
				200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		Pair<String, Boolean> passwordpolicyset = new Pair<>();
		passwordpolicyset.first("AllowUsersToChangePassword");
		passwordpolicyset.second(false);
		// updateaccountpassworpolicy为不允许修改密码
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwordpolicyset);
		// 创建密码。loginProfile为不允许所有用户修改密码
		create(accessKey, secretKey, user1Name, "createpassword", null, null);
		IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword, newPassword,
				403);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

		// 恢复默认passwordpolicy
		IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(accessKey, secretKey, 200);

	}

	/**
	 * 使用账户创建，未添加策略，passwordpolicy的AllowUsersToChangePassword为false
	 * HardExpiry为false且密码未过期，不允许修改
	 * HardExpiry为false且密码过期，则为不允许修改（为方便密码过期测试，修改代码passwordExpired的过期时间）
	 * HardExpiry为true，不允许修改
	 * HardExpiry仅控制前端页面能不能跳转到重置密码页，并不能决定是否可以修改密码权限
	 * 无changePassword策略时，根据AllowUsersToChangePassword为true/false进行允许/隐式拒绝
	 **/
	@Test
	public void test_changePassword_noPolicy_2() throws Exception {
		String oldPassword = "password123";
		String newPassword = "newpasswd123";

		Pair<String, Boolean> passwordpolicyset = new Pair<>();
		passwordpolicyset.first("AllowUsersToChangePassword");
		passwordpolicyset.second(false);
		// updateaccountpassworpolicy的AllowUsersToChangePassword为false，HardExpire为false
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwordpolicyset);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);

		// 密码未过期不允许修改密码
		IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword, newPassword,
				403);

		// 修改HardExpire为false，且密码过期，不允许修改密码
		passwordpolicyset.first("HardExpiry");
		passwordpolicyset.second(false);
		// updateaccountpassworpolicy的AllowUsersToChangePassword为false，HardExpire为false，MaxAge为1（设置为1则过期）
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwordpolicyset);
		IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword, newPassword,
				403);

		// 修改HardExpire为true，不允许修改密码
		passwordpolicyset.first("HardExpiry");
		passwordpolicyset.second(true);
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwordpolicyset);
		IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword, newPassword,
				403);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

	}
	
	
	/**
	 * 使用账户创建，未添加策略，passwordpolicy的AllowUsersToChangePassword为true
	 * HardExpiry为false且密码未过期，允许修改
	 * HardExpiry为false且密码过期，则为允许修改（为方便密码过期测试，修改代码passwordExpired的过期时间）
	 * HardExpiry为true，允许修改
	 * 无changePassword策略时，根据AllowUsersToChangePassword为true/false进行允许/隐式拒绝
	 **/
	@Test
	public void test_changePassword_noPolicy_3() throws Exception {
		String oldPassword = "password123";
		String newPassword = "newpasswd123";

		Pair<String, Boolean> passwordpolicyset = new Pair<>();
		passwordpolicyset.first("AllowUsersToChangePassword");
		passwordpolicyset.second(true);
		// updateaccountpassworpolicy的AllowUsersToChangePassword为false，HardExpire为false
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwordpolicyset);
		create(accessKey, secretKey, user1Name, "createpassword", null, null);

		// 密码未过期允许修改密码
		IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword, newPassword,
				200);

		// 修改HardExpire为false，且密码过期，允许修改密码
		passwordpolicyset.first("HardExpiry");
		passwordpolicyset.second(false);
		// updateaccountpassworpolicy的AllowUsersToChangePassword为false，HardExpire为false，MaxAge为1（设置为1则过期）
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwordpolicyset);
		IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, newPassword,oldPassword, 
				200);

		// 修改HardExpire为true，允许修改密码
		passwordpolicyset.first("HardExpiry");
		passwordpolicyset.second(true);
		create(accessKey, secretKey, user1Name, "accountpasswordpolicy", null, passwordpolicyset);
		IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword, newPassword,
				200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

	}
	
	

	/**
	 * 未添加策略 未设置passwordpolicy（不存在时，读取默认设置）
	 * 
	 **/
	@Test
	public void test_changePassword_noPolicy_user() throws Exception {
		String oldPassword = "password123";
		String newPassword = "newpasswd123";
		IAMInterfaceTestUtils.CreateLoginProfile(accessKey, secretKey, user1Name, "password123", 200);
		IAMInterfaceTestUtils.ChangePassword(user1accessKey1, user1secretKey1, user1Name, oldPassword, newPassword,
				200);
		IAMInterfaceTestUtils.DeleteLoginProfile(accessKey, secretKey, user1Name, 200);

	}
	
	

	// 用户权限
	public static void create(String ak, String sk, String userName, String action, String policyName,
			Pair<String, Boolean> passwordpolicyset) throws Exception {
		if (action.equals("putgetdeluserperssion")) {
			createPolicy(Effect.Allow, policyName, "Action",
					Arrays.asList("iam:CreateUser", "iam:DeleteUser", "iam:GetUser"), "Resource",
					Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
			String policyArn = "arn:ctyun:iam::" + accountId + ":policy/" + policyName;
			IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		}
		if (action.equals("createpassword"))
			IAMInterfaceTestUtils.CreateLoginProfile(ak, sk, userName, "password123", 200);
		if (action.equals("accountpasswordpolicy")) {
			String body = null;
			if (passwordpolicyset.first().equals("AllowUsersToChangePassword")) {
				body = "Action=UpdateAccountPasswordPolicy&Version=2010-05-08&AllowUsersToChangePassword="
						+ passwordpolicyset.second() + "&HardExpiry=false&MaxPasswordAge=0";
				Pair<Integer, String> update = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
				assertEquals(200, update.first().intValue());
			} else {
				if (passwordpolicyset.second() == true) {
					body = "Action=UpdateAccountPasswordPolicy&Version=2010-05-08&HardExpiry="
							+ passwordpolicyset.second() + "&MaxPasswordAge=0";
				} else
					body = "Action=UpdateAccountPasswordPolicy&Version=2010-05-08&HardExpiry="
							+ passwordpolicyset.second() + "&MaxPasswordAge=1";// 0或null表示永不过期

				Pair<Integer, String> update = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
				assertEquals(200, update.first().intValue());
			}
		}
		if (action.equals("createuser"))
			IAMInterfaceTestUtils.CreateUser(ak, sk, userName, 200);
		if (action.equals("loginprofileperssion")) {
			createPolicy(ak, sk, Effect.Allow, policyName, "Action",
					Arrays.asList("iam:CreateLoginProfile", "iam:GetLoginProfile", "iam:UpdateLoginProfile",
							"iam:DeleteLoginProfile"),
					"Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":user/*"), null);
			String policyArn = "arn:ctyun:iam::" + accountId + ":policy/" + policyName;
			IAMInterfaceTestUtils.AttachUserPolicy(ak, sk, accountId, userName, policyName, 200);
		}

	}

	// 创建策略
	public static void createPolicy(Effect effect, String policyName, String actionEffect, List<String> actions,
			String resourceEffect, List<String> resources, List<Condition> conditions) throws Exception {
		String policyDocument = IAMTestUtils.CreateOneStatementPolicyString(effect, null, null, actionEffect, actions,
				resourceEffect, resources, conditions);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + URLEncoder.encode(policyName)
				+ "&PolicyDocument=" + URLEncoder.encode(policyDocument) + "&Description=test_des";
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		System.out.println(result.second());
	}

	// 创建策略
	public static void createPolicy(String ak, String sk, Effect effect, String policyName, String actionEffect,
			List<String> actions, String resourceEffect, List<String> resources, List<Condition> conditions)
			throws Exception {
		String policyDocument = IAMTestUtils.CreateOneStatementPolicyString(effect, null, null, actionEffect, actions,
				resourceEffect, resources, conditions);
		String body = "Action=CreatePolicy&Version=2010-05-08&PolicyName=" + URLEncoder.encode(policyName)
				+ "&PolicyDocument=" + URLEncoder.encode(policyDocument) + "&Description=test_des";
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		System.out.println(result.second());
	}

	// 策略添加到用户
	public static void attachPolicyToUser(String userName, String policyArn) throws Exception {
		String bodyAttach = "Action=AttachUserPolicy&Version=2010-05-08&UserName=" + userName + "&PolicyArn="
				+ URLEncoder.encode(policyArn);
		Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(bodyAttach, accessKey, secretKey);
		assertEquals(200, result.first().intValue());
		System.out.println(result.second());
	}

	// 验证用户是否过期
	@Test
	public void test_userExpire() throws Exception {
		User user = new User();
		user.accountId = "0000000gc0uy9";
		user.userName = "test01_subuser01";
		user = HBaseUtils.get(user);
		boolean expire = user.passwordExpired(1);
		System.out.print("是否过期：" + expire);
	}

//	@Before
//	@Test
	public void setUpBeforeClass() throws Exception {
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

//		aksk1.accessKey = user1accessKey2;
//		aksk1.setSecretKey(user1secretKey2);
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
	
	/*
	 * 生成yyyy-MM-dd'T'HH:mm:ss'Z'格式的字符串
	 * 参数为相对今天的偏移量，0为今天，-1为昨天，1为明天以此类推
	 */
	public static String OneDay0UTCTimeString(int offset) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        Calendar calendar=Calendar.getInstance();
        calendar.add(Calendar.DATE ,offset);
        calendar.set(Calendar.HOUR_OF_DAY, 0);
        calendar.set(Calendar.MINUTE, 0);
        calendar.set(Calendar.SECOND, 0);
        Date date=calendar.getTime();
        String dayString=dateFormat.format(date);
        System.out.println(dayString);
        return dayString;
    }

}
