package cn.ctyun.oos.iam.accesscontroller;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.Arrays;

import org.jdom.JDOMException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.IpAddressCondition;
import cn.ctyun.oos.iam.server.result.AccessKeyResult;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import common.tuple.Pair;

public class IpAddressTestDev {
	//127.0.0.1
	//根用户
	public static final String accessKey="test_user8_6463084869102845087@a.cn88";
	public static final String secretKey="secretKey88";

	JsonPolicyWriter jsonPolicyWriter = new JsonPolicyWriter();

	PolicyTestToolDev policyTestTool = new PolicyTestToolDev();

	// 用户名
	String policyName = "policyForIpAddressCondition";
	String userName = "userForIpAddressCondition";
	String createUserName="createUserForIpAddressCondition";

	AccessKeyResult accessKeyResult;

	@Before
	public void before() throws JDOMException, IOException {

		String body;
		Pair<Integer, String> resultPair;

		// 创建一个用户
		body = "Action=CreateUser&Version=2010-05-08&UserName=" + userName;
		resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);

		// 给用户创建一个ak
		body="Action=CreateAccessKey&UserName=" + userName;
		resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		accessKeyResult = AccessKeyResultUtilsDev.convertToAccessKeyResult(resultPair.second());
	}

	@After
	public void after() {

		String body;
		Pair<Integer, String> resultPair;

		// 删除AK
		body="Action=DeleteAccessKey&AccessKeyId=" + accessKeyResult.accessKeyId + "&UserName=" + userName;
		resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
		// 删除用户
		body = "Action=DeleteUser&Version=2010-05-08&UserName=" + userName ;
		resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());
	}

	@Test
	public void testAllow() throws Exception {

		String body;
		Pair<Integer, String> resultPair;

		// 创建策略
		AccessPolicy accessPolicy = new AccessPolicy();
		Statement statement = new Statement(Effect.Allow);
		statement.actions.add("iam:CreateUser");
		statement.resources.add("arn:ctyun:iam::17vdu0cyjo7rh:user/*");
		// 添加条件
		Condition condition=new IpAddressCondition("IpAddress","ctyun:SourceIp",Arrays.asList("127.0.0.10/24"));
		//Condition condition=new IpAddressCondition("NotIpAddress","ctyun:SourceIp","127.0.0.0","127.0.0.3");
		statement.conditions.add(condition);
		accessPolicy.statements.add(statement);

		String json = jsonPolicyWriter.writePolicyToString(accessPolicy);
		System.out.println(json);
		// 创建策略
		policyTestTool.createPolicy(policyName, json);

		// 无权限请求失败
		body = "Action=CreateUser&Version=2010-05-08&UserName=" + createUserName;
		resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
		assertEquals(403, resultPair.first().intValue());

		// 附加策略
		policyTestTool.attachUserPolicy(policyName, userName);

		// 有权限请求成功
		body = "Action=CreateUser&Version=2010-05-08&UserName=" + createUserName;
		resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
		assertEquals(200, resultPair.first().intValue());
		//assertEquals(403, resultPair.first().intValue());

		body = "Action=DeleteUser&Version=2010-05-08&UserName=" + createUserName;
		resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200, resultPair.first().intValue());

		// 清除策略附加
		policyTestTool.detachUserPolicy(policyName, userName);
		// 删除策略 
		policyTestTool.deletePolicy(policyName);
	}


	@Test
	public void testDeny() throws Exception {

		String body;
		Pair<Integer, String> resultPair;

		// 创建策略
		AccessPolicy accessPolicy = new AccessPolicy();
		Statement statement = new Statement(Effect.Deny);
		statement.actions.add("iam:CreateUser");
		statement.resources.add("arn:ctyun:iam::17vdu0cyjo7rh:user/*");
		// 添加条件
		Condition condition=new IpAddressCondition("IpAddress","ctyun:SourceIp",Arrays.asList("127.0.0.0/1"));
		//Condition condition=new IpAddressCondition("NotIpAddress","ctyun:SourceIp","127.0.0.0/24");
		statement.conditions.add(condition);
		accessPolicy.statements.add(statement);

		String json = jsonPolicyWriter.writePolicyToString(accessPolicy);
		System.out.println(json);

		// 创建策略
		policyTestTool.createPolicy(policyName, json);

		// 无权限请求失败
		body = "Action=CreateGroup&Version=2010-05-08&GroupName=" + createUserName;
		resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
		assertEquals(403, resultPair.first().intValue());

		// 附加策略
		policyTestTool.attachUserPolicy(policyName, userName);

		// 继续请求失败
		body = "Action=CreateGroup&Version=2010-05-08&GroupName=" + createUserName;
		resultPair = IAMTestUtils.invokeHttpsRequest(body, accessKeyResult.accessKeyId, accessKeyResult.secretAccessKey);
		assertEquals(403, resultPair.first().intValue());

		// 清除策略附加
		policyTestTool.detachUserPolicy(policyName, userName);
		// 删除策略 
		policyTestTool.deletePolicy(policyName);
	}

}
