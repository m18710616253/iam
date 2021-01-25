package cn.ctyun.oos.iam.test.oosaccesscontrol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.StringReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.common.Consts;
import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.hbase.HBaseUserToTag;
import cn.ctyun.oos.hbase.HBaseVSNTag;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.metadata.UserToTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta.VSNTagType;
import common.tuple.Pair;

public class OOSObjectAPIAccessTest {
	public String bucketName = "privatebk1"; //为privateBucket
	public String bucketName2 = "privatebk2";//为privateBucket
	public String publicBucketName = "publicbk";
	public String publicBucketName2 = "publicbk2";
	public String onlyReadBucketName = "readbk";
	public String onlyReadBucketName2 = "readbk2";
	public String objectName = "obj1";
	public String objectName2 = "obj2";
	public int jettyPort = 8080; // 8443 8080
	public String http = "http";
	public String signVersion = "V4";

	public static final String OOS_IAM_DOMAIN = "https://oos-loc6-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName = "loc6";

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
	static Configuration globalConf = GlobalHHZConfig.getConfig();

	/**
	 * 私有bucket代表了隐式拒绝
	 * 子用户测试
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_noPolicy_private_test() {
		// root用户上传对象
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == rootPut.first());

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put.first());
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap());
		assertTrue(403 == head);
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(403 == get.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(403 == delete.first());

		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap());
		assertTrue(204 == rootDelete.first());
	}
	

	/***
	 * bucket为公有，不需要iam策略也可以访问oos Object
	 * 公有bucket代表了显示允许
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_noPolicy_public_test() {
		// putObject成功
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, publicBucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == put.first());

		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				publicBucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == head);
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, publicBucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == get.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, publicBucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == delete.first());
	}
	
	/***
	 * bucket为只读，代表显示允许了get和head，其他操作隐式拒绝。
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_noPolicy_onlyRead_test() {
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, accessKey,
				secretKey, onlyReadBucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, onlyReadBucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(403 == put.first());
		
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, onlyReadBucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == head);
		
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, onlyReadBucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == get.first());
		
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, onlyReadBucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == delete.first());
		
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				accessKey, secretKey, onlyReadBucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		
	}

	/***
	 * bucket为公有，策略为deny
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_deny_public_test() {
		String policyName = "putGetDelObject_denyAll";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		// putObject成功
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, accessKey,
				secretKey, publicBucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, publicBucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(403 == put.first());

		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				publicBucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == head);
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, publicBucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == get.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, publicBucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == delete.first());
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				accessKey, secretKey, publicBucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}
	
	/***
	 * bucket为私有，策略为allow
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_allow_private_test() {
		String policyName = "putGetDelObject_allowAll";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == put.first());

		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == head);
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == get.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == delete.first());
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_allow_action_all_test() {
		String policyName = "putGetDelObject_allowAll";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == put.first());
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == get.first());
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == head);
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == delete.first());

		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName2, objectName2, "helloworld", new HashMap<String, String>());
		assertTrue(200 == put2.first());
		Pair<Integer, String> get2 = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName2, objectName2, new HashMap<String, String>());
		assertTrue(200 == get2.first());
		int head2 = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName2, objectName2, new HashMap<String, String>());
		assertTrue(200 == head2);
		Pair<Integer, String> delete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName2, objectName2, new HashMap<String, String>());
		assertTrue(204 == delete2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_allow_action_bucketName_test() {
		String policyName = "putGetDelObject_bucketName";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == put.first());
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == get.first());
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == head);
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == delete.first());

		// 策略不匹配，bucketName不匹配，putObject失败
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName2, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(403 == put2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_allow_action_objectName_test() {
		String policyName = "putGetDelObject_objectName";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 策略匹配
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put.first());
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap());
		assertTrue(200 == head);
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(200 == get.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(204 == delete.first());

		// root用户上传对象
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName2, "helloworld", new HashMap());
		assertTrue(200 == rootPut.first());
		// 策略不匹配
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName2, "helloworld", new HashMap<String, String>());
		assertTrue(403 == put2.first());
		int head2 = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName2, new HashMap<String, String>());
		assertTrue(403 == head2);
		Pair<Integer, String> get2 = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(403 == get2.first());
		Pair<Integer, String> delete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(403 == delete2.first());
		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_allow_action_resourceNotMatch_test() {
		String policyName = "putGetDelObject_allow_resourceNotMatch";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 策略匹配
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put.first());
		Pair<Integer, String> rootput = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == rootput.first());
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap());
		assertTrue(403 == head);
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(403 == get.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(403 == delete.first());
		Pair<Integer, String> rootdelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				accessKey, secretKey, bucketName, objectName, new HashMap());
		assertTrue(204 == rootdelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_allow_action_notResource_bucketName_test() {
		String policyName = "putGetDelObject_notResource_bucketName";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName2 + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 策略匹配
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == put.first());
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == get.first());
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == head);
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(204 == delete.first());

		// 策略匹配，putObject失败,隐式拒绝
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName2, objectName, "helloworld", new HashMap());
		assertTrue(403 == put2.first());
		// root用户上传对象
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName2, objectName, "helloworld", new HashMap());
		assertTrue(200 == rootPut.first());
		Pair<Integer, String> get2 = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName2, objectName, new HashMap());
		assertTrue(403 == get2.first());
		int head2 = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName2, objectName, new HashMap());
		assertTrue(403 == head2);
		Pair<Integer, String> delete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName2, objectName, new HashMap());
		assertTrue(403 == delete2.first());

		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_allow_notAction_bucketName_test() {
		String policyName = "putGetDelObject_notAction_bucketName";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:PutObject", "oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 策略不匹配，putObject失败
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put.first());

		// root用户上传对象
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == rootPut.first());

		// 策略不匹配，getObject失败
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(403 == get.first());

		// 策略不匹配，headObject失败
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap());
		assertTrue(403 == head);

		// 策略匹配，deleteObject成功
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(204 == delete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_allow_notAction_objectName_test() {
		// 创建policy
		String policyName = "putGetDelObject_notAction_objectName";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:PutObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 策略不匹配，putObject失败
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put.first());

		// root用户上传对象
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == rootPut.first());

		// 策略匹配，getObject成功
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(200 == get.first());

		// 策略匹配，headObject成功
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap());
		assertTrue(200 == head);

		// 策略不匹配，deleteObject失败
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(403 == delete.first());

		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_allow_notAction_notResourceBucket_test() {
		String policyName = "putGetDelObject_notAction_notResource_bucket";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:DeleteObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 允许创建策略
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, policyName, policyString, 200);

		// putObject失败，resource不匹配，拒绝在test01中put对象
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(403 == put.first());

		// 策略匹配，putObject成功
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName2, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == put2.first());

		// 策略匹配，getObject成功
		Pair<Integer, String> get2 = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName2, objectName, new HashMap<String, String>());
		assertTrue(200 == get2.first());

		// 策略匹配，headObject成功
		int head2 = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName2, objectName, new HashMap<String, String>());
		assertTrue(200 == head2);

		// notAction,隐式拒绝deleteObject
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName2, objectName, new HashMap<String, String>());
		assertTrue(403 == delete.first());

		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName2, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_allow_notAction_notResourceObject_test() {
		String policyName = "putGetDelObject_notAction_notResource_objectName";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:DeleteObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 创建策略成功
		IAMInterfaceTestUtils.CreatePolicy(user1accessKey1, user1secretKey1, policyName, policyString, 200);

		// putObject失败，resource不匹配，拒绝在test01中put对象
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(403 == put.first());

		// 策略匹配，putObject成功
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName2, "helloworld", new HashMap<String, String>());
		assertTrue(200 == put2.first());

		// 策略匹配，getObject成功
		Pair<Integer, String> get2 = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(200 == get2.first());

		// 策略匹配，headObject成功
		int head2 = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName2, new HashMap<String, String>());
		assertTrue(200 == head2);

		// notAction,隐式拒绝deleteObject
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(403 == delete.first());

		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_allow_action_condition_StringLike_test() {
		String policyName = "putGetDelObject_condition_stringLike";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test_1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		// 策略匹配，putObject成功
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put.first());

		// 策略匹配，headObject成功
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap());
		assertTrue(200 == head);

		// 策略匹配，getObject成功
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(200 == get.first());

		// 策略匹配，deleteObject成功
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(204 == delete.first());

		// 策略不匹配，bucketName不匹配，putObject失败
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName2, objectName, "helloworld", new HashMap());
		assertTrue(403 == put2.first());

		// 策略不匹配，condition不匹配，putObject失败
		Pair<Integer, String> put3 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName2, objectName, "helloworld", new HashMap());
		assertTrue(403 == put3.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_allow_action_condition_StringEqualsIgnoreCase_test() {
		String policyName = "putGetDelObject_condition_StringEqualsIgnoreCase";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions
				.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase", "ctyun:username", Arrays.asList("Test_1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		// 策略匹配，putObject成功
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put.first());

		// 策略匹配，getObject成功
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap());
		assertTrue(200 == head);

		// 策略匹配，getObject成功
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(200 == get.first());

		// 策略匹配，deleteObject成功
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(204 == delete.first());

		// 策略不匹配，bucketName不匹配，putObject失败
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName2, objectName, "helloworld", new HashMap());
		assertTrue(403 == put2.first());

		// 策略不匹配，condition不匹配，putObject失败
		Pair<Integer, String> put3 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName2, objectName, "helloworld", new HashMap());
		assertTrue(403 == put3.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_deny_action_resourceNotMatch_test() {
		String policyName = "putGetDelObject_deny_resourceNotMatch";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":group/testGroup01"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String policyName2 = "putGetDelObject_allow";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

		// 第一条策略，显示拒绝未生效，所以结果是显示允许
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put.first());
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap());
		assertTrue(200 == head);
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(200 == get.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(204 == delete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_deny_action_bucketName_test() {
		String policyName = "putGetDelObject_Deny_bucketName";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 策略不匹配，putObject失败
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(403 == put.first());

		// root用户上传对象
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());

		// 策略不匹配，getObject失败，隐式拒绝
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == get.first());

		// 策略不匹配，headObject失败，隐式拒绝
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == head);

		// 策略不匹配，deleteObject失败
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == delete.first());

		// 显示允许getObject
		String policyName2 = "putGetDelObject_Deny2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> get2 = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == get2.first());

		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_deny_action_objectName_test() {
		String policyName = "putGetDelObjectDeny";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 策略不匹配，putObject失败
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(403 == put.first());

		// root用户上传对象
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());

		// 策略不匹配，getObject失败，隐式拒绝
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == get.first());

		// 策略不匹配，headObject失败，隐式拒绝
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == head);

		// 策略不匹配，deleteObject失败
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == delete.first());

		// 显示允许getObject
		String policyName2 = "putGetDelObjectDeny2";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> get2 = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == get2.first());

		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	/**
	 * 第一条策略，显示拒绝了“除oos:GetObject”之外的操作 在 “test01/obj1” 上的资源的访问。
	 * 第二条策略，显示允许了PutObject和GetObject在“test01/*”上的访问。
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_deny_notAction_resource_test() {
		// 创建policy
		String policyName = "denyNotAction", policyName2 = "allowAciton";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 策略不匹配，putObject失败
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, "obj2", "helloworld", new HashMap<String, String>());
		assertTrue(403 == put.first());

		// root用户上传对象
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());

		// 策略不匹配，getObject失败，隐式拒绝
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == get.first());

		// 策略不匹配，headObject失败，隐式拒绝
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == head);

		// 策略不匹配，deleteObject失败
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == delete.first());

		// 显示允许getObject,putObject, test01/*
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName2, "helloworld", new HashMap<String, String>());
		assertTrue(200 == put2.first());
		Pair<Integer, String> put3 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(403 == put3.first());
		Pair<Integer, String> get2 = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(200 == get2.first());
		Pair<Integer, String> get3 = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == get3.first());

		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		Pair<Integer, String> rootDelete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(204 == rootDelete2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	/**
	 * 第一条策略，显示拒绝了“除oos:GetObject”之外的操作 在 “test01/obj1”之外的资源的访问。
	 * 第二条策略，显示允许了PutObject和GetObject在“test01/*”上的访问。
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_deny_notAction_notResource_test() {
		String policyName = "denyNotActionNotResource", policyName2 = "allowAciton";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// putObject失败，显示拒绝
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName2, "helloworld", new HashMap<String, String>());
		assertTrue(403 == put.first());
		// putObject失败，隐式拒绝
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(403 == put2.first());

		// root用户上传对象
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		Pair<Integer, String> rootPut2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName2, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut2.first());

		// getObject失败，隐式拒绝
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == get.first());

		// headObject失败，隐式拒绝
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == head);

		// deleteObject失败,隐式拒绝
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == delete.first());

		// 显示允许getObject,putObject, test01/*
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> put3 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == put3.first());
		Pair<Integer, String> put4 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName2, "helloworld", new HashMap<String, String>());
		assertTrue(403 == put4.first());
		Pair<Integer, String> get2 = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == get2.first());
		Pair<Integer, String> get3 = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(200 == get3.first());

		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		Pair<Integer, String> rootDelete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(204 == rootDelete2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	/**
	 * 1个策略2个statement 第一个stat:显示拒绝了PutObject，DeleteObject 第二个stat显示允许了GetObject
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void putHeadGetDelObject_action_twoStat_test() {
		String policyName = "putGetDelObject_twoStat";
		List<Statement> statements = new ArrayList<Statement>();
		Statement s1 = IAMTestUtils.CreateStatement(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		statements.add(s1);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		Statement s2 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "Action", Arrays.asList("oos:GetObject"),
				"Resource", Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		statements.add(s2);
		String policyString = IAMTestUtils.CreateMoreStatement(statements);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 策略不匹配，putObject失败
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(403 == put.first());

		// root用户上传对象
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());

		// 策略匹配，getObject成功
		Pair<Integer, String> get = OOSInterfaceTestUtils.Object_Get(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == get.first());

		// 策略匹配，getObject成功
		int head = OOSInterfaceTestUtils.Object_Head(http, signVersion, jettyPort, user1accessKey1, user1secretKey1,
				bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == head);

		// 策略不匹配，deleteObject失败
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == delete.first());

		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void postObject_allow_all_test() {
		String policyName = "postObject_allowAll";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource", Arrays.asList("arn:ctyun:oos::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Post2(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld");
		assertTrue(204 == put.first());
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void postObject_allow_action_test() {
		String policyName = "postObject_allow";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Post2(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld");
		assertTrue(204 == put.first());
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void postObject_allow_resourceNotMatch_test() {
		String policyName = "postObject_resourceNotMatch";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Post2(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld");
		assertTrue(403 == put.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void postObject_allow_action_notResource_test() {
		String policyName = "postObject_notResource";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Post2(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld");
		assertTrue(403 == put.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void postObject_allow_NotAction_test() {
		String policyName = "postObject_notAction";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Post2(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld");
		assertTrue(204 == put.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void postObject_allow_NotAction_notResource_test() {
		String policyName = "postObject_notAction_notResource";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Post2(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld");
		assertTrue(403 == put.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void postObject_deny_resourceNotMatch_test() {
		String policyName = "postObject_deny_resourceNotMatch";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource", Arrays.asList("arn:ctyun:iam::" + accountId + ":mfa/*"),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String policyName2 = "postObject_allow_policy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

		// 第一条策略显示拒绝不生效，所以结果是显示允许
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Post2(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld");
		assertTrue(204 == put.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void postObject_deny_action_test() {
		String policyName = "postObject_deny_action";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Post2(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld");
		assertTrue(403 == put.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void postObject_deny_notAction_test() {
		String policyName = "postObject_deny_notAction";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Post2(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld");
		assertTrue(403 == put.first());

		String policyName2 = "postObject_allowPut";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Post2(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld");
		assertTrue(204 == put2.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void postObject_deny_notAction_notResource_test() {
		String policyName2 = "postObject_allowPut";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Post2(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld");
		assertTrue(204 == put2.first());

		String policyName = "postObject_deny_notAction";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName2), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Post2(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld");
		assertTrue(403 == put.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	/**
	 * 根用户
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void copyObject_allow_action_rootUser_test() {
		String srcobjectName = "srcobj", desobjectName = "desobj";
		String policyName = "copyObject";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName2, srcobjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("x-amz-copy-source", "/" + bucketName2 + "/" + srcobjectName);
		Pair<Integer, String> copy = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, accessKey, secretKey,
				bucketName, srcobjectName, desobjectName, map);
		assertTrue(200 == copy.first());
		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, srcobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		Pair<Integer, String> rootDelete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, desobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}
	
	/**
	 * 源bucket和目标bucket均为私有
	 * 子用户测试
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void copyObject_noPolicy_private_test() {
		String srcobjectName = "srcobj", desobjectName = "desobj";

		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName, srcobjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("x-amz-copy-source", "/" + bucketName + "/" + srcobjectName);
		Pair<Integer, String> copy = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName2, srcobjectName, desobjectName, map);
		assertTrue(403 == copy.first());
		System.out.println(copy.second());
		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, srcobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
	}
	
	
	/**
	 * 源bucket和目标bucket均为私有
	 * 子用户测试
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void copyObject_noPolicy_public_test() {
		String srcobjectName = "srcobj", desobjectName = "desobj";

		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				publicBucketName, srcobjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("x-amz-copy-source", "/" + publicBucketName + "/" + srcobjectName);
		Pair<Integer, String> copy = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, publicBucketName2, srcobjectName, desobjectName, map);
		assertTrue(200 == copy.first());
		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, publicBucketName, srcobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		
		Pair<Integer, String> rootDelete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, publicBucketName2, desobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete2.first());
	}
	
	/**
	 * 源bucket为只读，目标bucket为公有
	 * 子用户测试
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void copyObject_noPolicy_readpublic_test() {
		String srcobjectName = "srcobj", desobjectName = "desobj";

		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				onlyReadBucketName, srcobjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("x-amz-copy-source", "/" + onlyReadBucketName + "/" + srcobjectName);
		Pair<Integer, String> copy = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, publicBucketName, srcobjectName, desobjectName, map);
		assertTrue(200 == copy.first());
		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, publicBucketName, srcobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		
		Pair<Integer, String> rootDelete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, onlyReadBucketName, desobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete2.first());
	}

	/**
	 * 子用户只拥有对目标对象的PutObject的权限，没有对源对象的GetObject权限，报403
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void copyObject_allow_action_subUser_test() {
		String srcobjectName = "srcobj", desobjectName = "desobj";
		String policyName = "copyObject";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName2, srcobjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("x-amz-copy-source", "/" + bucketName2 + "/" + srcobjectName);
		Pair<Integer, String> copy = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, srcobjectName, desobjectName, map);
		assertTrue(403 == copy.first());
		System.out.println(copy.second());
		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, srcobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/**
	 * 子用户拥有对目标对象的PutObject的权限，且拥有对源对象的GetObject权限
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void copyObject_allow_action_subUser_test2() {
		String srcobjectName = "srcobj", desobjectName = "desobj";
		String policyName = "copyObject";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String policyName2 = "getObject";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName2 + "/" + srcobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName2, srcobjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("x-amz-copy-source", "/" + bucketName2 + "/" + srcobjectName);
		Pair<Integer, String> copy = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, srcobjectName, desobjectName, map);
		assertTrue(200 == copy.first());
		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName2, srcobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		Pair<Integer, String> rootDelete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, desobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@Test
	public void copyObject_allow_action_resourceNotMatch_test() {
		String srcobjectName = "srcobj", desobjectName = "desobj";
		String policyName = "copyObject";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName2 + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String policyName2 = "getObject";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName2 + "/" + srcobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName2, srcobjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("x-amz-copy-source", "/" + bucketName2 + "/" + srcobjectName);
		Pair<Integer, String> copy = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, srcobjectName, desobjectName, map);
		assertTrue(403 == copy.first());
		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName2, srcobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}
	

	@SuppressWarnings("unchecked")
	@Test
	public void copyObject_allow_action_notResource_test() {
		String srcobjectName = "srcObj", desobjectName = "desObj";
		String policyName = "copyObject_notResource";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + srcobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String policyName2 = "getObject";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName2 + "/" + srcobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName2, srcobjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("x-amz-copy-source", "/" + bucketName2 + "/" + srcobjectName);
		Pair<Integer, String> copy = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, srcobjectName, desobjectName, map);
		assertTrue(200 == copy.first());
		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName2, srcobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		Pair<Integer, String> rootDelete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, desobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void copyObject_allow_notAction_test() {
		String srcobjectName = "obj1", desobjectName = "obj2";
		String policyName = "copyObject_notAction";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + desobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String policyName2 = "getObject";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName2 + "/" + srcobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName2, srcobjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("x-amz-copy-source", "/" + bucketName2 + "/" + srcobjectName);
		Pair<Integer, String> copy = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, srcobjectName, desobjectName, map);
		assertTrue(403 == copy.first());
		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, srcobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void copyObject_allow_notAction_notResource_test() {
		String srcobjectName = "obj1", desobjectName = "obj2";
		String policyName = "copyObject_notAction_notResource";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + srcobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String policyName2 = "getObject";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName2 + "/" + srcobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName2, srcobjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("x-amz-copy-source", "/" + bucketName2 + "/" + srcobjectName);
		Pair<Integer, String> copy = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, srcobjectName, desobjectName, map);
		assertTrue(200 == copy.first());

		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, srcobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, desobjectName, new HashMap<String, String>());
		assertTrue(204 == delete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void copyObject_deny_resourceNotMatch_test() {
		String srcobjectName = "srcobj", desobjectName = "desobj";
		String policyName = "copyObject_deny_resourceNotMatch";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:iam::" + accountId + ":" + bucketName2 + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String policyName2 = "copyObject_allow_policy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

		String policyName3 = "getObject";
		String policyString3 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName2 + "/" + srcobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName3, 200);
		
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName2, srcobjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("x-amz-copy-source", "/" + bucketName2 + "/" + srcobjectName);
		Pair<Integer, String> copy = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, srcobjectName, desobjectName, map);
		assertTrue(200 == copy.first());
		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, srcobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		Pair<Integer, String> rootDelete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, desobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName3, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName3, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void copyObject_deny_action_test() {
		String srcobjectName = "obj1", desobjectName = "obj2";
		String policyName = "copyObject_Deny_Action";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + desobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String policyName2 = "getObject";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName2 + "/" + srcobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName2, srcobjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("x-amz-copy-source", "/" + bucketName2 + "/" + srcobjectName);
		Pair<Integer, String> copy = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, srcobjectName, desobjectName, map);
		assertTrue(403 == copy.first());
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, srcobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void copyObject_deny_notAction_test() {
		String srcobjectName = "obj1", desobjectName = "obj2";
		String policyName = "copyObject_Deny_NotAction";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + desobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String policyName3 = "getObject";
		String policyString3 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName2 + "/" + srcobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName3, 200);
		
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName2, srcobjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("x-amz-copy-source", "/" + bucketName2 + "/" + srcobjectName);
		Pair<Integer, String> copy = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, srcobjectName, desobjectName, map);
		assertTrue(403 == copy.first());

		String policyName2 = "copyObject_alowPut";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName2), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

		HashMap<String, String> map2 = new HashMap<String, String>();
		map2.put("x-amz-copy-source", "/" + bucketName2 + "/" + srcobjectName);
		Pair<Integer, String> copy2 = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, srcobjectName, desobjectName, map2);
		assertTrue(200 == copy2.first());

		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, srcobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, desobjectName, new HashMap<String, String>());
		assertTrue(204 == delete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName3, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName3, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void copyObject_deny_notAction_notResource_test() {
		String srcobjectName = "obj1", desobjectName = "obj2";
		String policyName = "copyObject_Deny_NotAction";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:PutObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + srcobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String policyName3 = "getObject";
		String policyString3 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName2 + "/" + srcobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName3, 200);
		
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName, srcobjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("x-amz-copy-source", "/" + bucketName2 + "/" + srcobjectName);
		Pair<Integer, String> copy = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, srcobjectName, desobjectName, map);
		assertTrue(403 == copy.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		String policyName2 = "copyObject_alowPut";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + desobjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

		HashMap<String, String> map2 = new HashMap<String, String>();
		map2.put("x-amz-copy-source", "/" + bucketName2 + "/" + srcobjectName);
		Pair<Integer, String> copy2 = OOSInterfaceTestUtils.Object_Copy(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, srcobjectName, desobjectName, map2);
		assertTrue(200 == copy2.first());

		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, srcobjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, desobjectName, new HashMap<String, String>());
		assertTrue(204 == delete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName3, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName3, 200);
	}

	/**
	 * 根用户
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void copyPart_allow_action_rootUser_test() {
		String sourceObjectName = "obj1", objectName = "obj2", policyName = "copyPartPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, sourceObjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		Pair<Integer, String> copyPartResult = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort, accessKey,
				secretKey, bucketName, objectName, uploadId, 1, sourceObjectName, new HashMap());
		assertTrue(200 == copyPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/**
	 * 子用户只拥有目标对象的PutObject权限，没有源对象的GetObject权限
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void copyPart_allow_action_subUser_test() {
		String sourceObjectName = "obj1", objectName = "obj2", policyName = "copyPartPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, sourceObjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		Pair<Integer, String> copyPartResult = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, sourceObjectName, new HashMap());
		assertTrue(403 == copyPartResult.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}
	
	/**
	 * 子用户只拥有目标对象的PutObject权限，且拥有对源对象的GetObject权限
	 *
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void copyPart_allow_action_subUser_test2() {
		String sourceObjectName = "obj1", objectName = "obj2", policyName = "copyPartPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String policyName3 = "getObject";
		String policyString3 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + sourceObjectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName3, 200);
		
		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, bucketName, sourceObjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		Pair<Integer, String> copyPartResult = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, sourceObjectName, new HashMap());
		assertTrue(200 == copyPartResult.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, sourceObjectName, new HashMap<String, String>());
		assertTrue(204 == delete.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName3, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName3, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void copyPart_allow_action_notResource_test() {
		String sourceObjectName = "obj1", objectName = "obj2", policyName = "copyPart_notResource";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject","oos:GetObject", "oos:ListMultipartUploadParts"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/objtest"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName, sourceObjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());

		Pair<Integer, String> copyPartResult = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, sourceObjectName, new HashMap());
		assertTrue(200 == copyPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, sourceObjectName, new HashMap<String, String>());
		assertTrue(204 == delete.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void copyPart_allow_notAction_test() {
		String sourceObjectName = "obj1", objectName = "obj2", policyName = "copyPart_notAction";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName, sourceObjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());

		Pair<Integer, String> copyPartResult = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, sourceObjectName, new HashMap());
		assertTrue(200 == copyPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, sourceObjectName, new HashMap<String, String>());
		assertTrue(204 == delete.first());
		Pair<Integer, String> delete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == delete2.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void copyPart_allow_notAction_notResource_test() {
		String sourceObjectName = "obj1", objectName = "obj2", policyName = "copyPart_notAction_notResource";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:DeleteObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + "hhha"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName, sourceObjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());

		Pair<Integer, String> copyPartResult = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, sourceObjectName, new HashMap());
		assertTrue(200 == copyPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, sourceObjectName, new HashMap<String, String>());
		assertTrue(204 == delete.first());
		Pair<Integer, String> delete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == delete2.first());
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void copyPart_deny_action_test() {
		String sourceObjectName = "obj1", objectName = "obj2", policyName = "copyPart_allowPut";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject","oos:GetObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName, sourceObjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		Pair<Integer, String> copyPartResult = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, sourceObjectName, new HashMap());
		assertTrue(200 == copyPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());

		String policyName2 = "copyPart_denyPut";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> copyPartResult2 = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, sourceObjectName, new HashMap());
		assertTrue(403 == copyPartResult2.first());
		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, sourceObjectName, new HashMap<String, String>());
		assertTrue(204 == delete.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void copyPart_deny_notAction_test() {
		String sourceObjectName = "obj1", objectName = "obj2", policyName = "copyPart_allowPut";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject","oos:GetObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName, sourceObjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		Pair<Integer, String> copyPartResult = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, sourceObjectName, new HashMap());
		assertTrue(200 == copyPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());

		String policyName2 = "copyPart_denyPut_notAction";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> copyPartResult2 = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, sourceObjectName, new HashMap());
		assertTrue(403 == copyPartResult2.first());

		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, sourceObjectName, new HashMap<String, String>());
		assertTrue(204 == delete.first());
		Pair<Integer, String> delete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == delete2.first());
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void copyPart_deny_notAction_notResource_test() {
		String sourceObjectName = "obj1", objectName = "obj2", policyName = "copyPart_allowPut";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject","oos:GetObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey, secretKey,
				bucketName, sourceObjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		Pair<Integer, String> copyPartResult = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, sourceObjectName, new HashMap());
		assertTrue(200 == copyPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());

		String policyName2 = "copyPart_denyPut_notAction_notResource";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> copyPartResult2 = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, sourceObjectName, new HashMap());
		assertTrue(200 == copyPartResult2.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	/**
	 * 无策略 bucket属性为共有 可以操作访问
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void multiPart_noPolicy_public_test() {
		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, publicBucketName, objectName,
				new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, publicBucketName, objectName, uploadId, 1, "aaaaaaa", new HashMap());
		assertTrue(200 == uploadPartResult.first());

		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, publicBucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());
		
		String sourceObjectName = "srcObj";
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, user1accessKey1,
				user1secretKey1, publicBucketName, sourceObjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		Pair<Integer, String> copyPartResult = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort,
				user1accessKey1, user1secretKey1, publicBucketName, objectName, uploadId, 2, sourceObjectName, new HashMap());
		assertTrue(200 == copyPartResult.first());

		Map<String, String> partEtagMap = new HashMap<String, String>();
		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, publicBucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(200 == completeResult.first());
		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, publicBucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		Pair<Integer, String> rootDelete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, publicBucketName, sourceObjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete2.first());
	}

	/**
	 * 无策略 bucket为私有 默认无权限操作oos
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void multiPart_noPolicy_private_test() {
		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == initialResult.first());

		Pair<Integer, String> rootInitialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, accessKey, secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == rootInitialResult.first());
		String initialXml = rootInitialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "aaaaaaa",
				new HashMap<String, String>());
		assertTrue(403 == uploadPartResult.first());

		Pair<Integer, String> rootUploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion,
				jettyPort, accessKey, secretKey, bucketName, objectName, uploadId, 1, "clientContent",
				new HashMap<String, String>());
		assertTrue(200 == rootUploadPartResult.first());

		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap<String, String>());
		assertTrue(403 == listPartsResult.first());

		Pair<Integer, String> rootlistPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				accessKey, secretKey, bucketName, objectName, uploadId, new HashMap<String, String>());
		assertTrue(200 == rootlistPartsResult.first());
		
		String sourceObjectName = "srcObj";
		Pair<Integer, String> rootPut = OOSInterfaceTestUtils.Object_Put(http, "V4", jettyPort, accessKey,
				secretKey, bucketName, sourceObjectName, "helloworld", new HashMap<String, String>());
		assertTrue(200 == rootPut.first());
		Pair<Integer, String> copyPartResult = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 2, sourceObjectName, new HashMap());
		assertTrue(403 == copyPartResult.first());
		Pair<Integer, String> rootcopyPartResult = OOSInterfaceTestUtils.Object_CopyPart(http, "V4", jettyPort,
				accessKey, secretKey, bucketName, objectName, uploadId, 2, sourceObjectName, new HashMap());
		assertTrue(200 == rootcopyPartResult.first());

		Map<String, String> partEtagMap = new HashMap<String, String>();
		partEtagMap.put("1", rootUploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(403 == completeResult.first());
		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		Pair<Integer, String> rootDelete2 = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, sourceObjectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete2.first());
		
	}

	/**
	 * 分段上传测试 Effect：Allow Action：oos:PutObject Resource：* condition:IpAddress
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void multiPart_allow_action_all_test() {
		// 创建policy
		String policyName = "multipartPolicy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource", Arrays.asList("arn:ctyun:oos::" + accountId + ":*"),
				conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "aaaaaaa", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Map<String, String> partEtagMap = new HashMap<String, String>();
		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(200 == completeResult.first());

		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void multiPart_allow_action_bucketName_test() {
		String objectName = "obj1", policyName = "multipartPolicy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "aaaaaaa", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Map<String, String> partEtagMap = new HashMap<String, String>();
		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(200 == completeResult.first());

		Pair<Integer, String> initialResult2 = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName2, objectName, new HashMap<String, String>());
		assertTrue(403 == initialResult2.first());

		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void multiPart_allow_action_objectName_test() {
		String policyName = "multipartPolicy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "aaaaaaa", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Map<String, String> partEtagMap = new HashMap<String, String>();
		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(200 == completeResult.first());

		Pair<Integer, String> initialResult2 = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(403 == initialResult2.first());

		// root用户删除对象
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void initialPart_allow_action_ResourceNotMatch_test() {
		String policyName = "notResourceMatchPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == initialResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/**
	 * 初始化分段上传 Effect：Allow NotAction：oos:PutObject Resource：bucket/* condition:null
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void initialPart_allow_action_notResource_test() {
		// 创建policy
		String policyName = "notResourcePolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == initialResult.first());

		Pair<Integer, String> initialResult2 = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName2, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/**
	 * 初始化分段上传 Effect：Allow NotAction：oos:PutObject Resource：bucket/*
	 * condition:IpAddress
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void initialPart_allow_notAction_bucketName_test() {
		// 创建policy
		String policyName = "multipartPolicyNotActionBukcet";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void initialPart_allow_notAction_objectName_test() {
		String policyName = "multipartPolicyNotAction";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == initialResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void initialPart_allow_notAction_notResource_test() {
		String policyName = "multipartPolicyNotAction_notResource";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == initialResult.first());

		Pair<Integer, String> initialResult2 = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(200 == initialResult2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void initialPart_deny_action_ResourceNotMatch_test() {
		String policyName = "deny_notResourceMatchPolicy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		String policyName2 = "allow_policy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void initialPart_deny_action_bucketName_test() {
		String policyName = "initialdenyDeny";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == initialResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void initialPart_deny_action_objectName_test() {
		String policyName = "initialdenyDeny";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 显示拒绝
		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == initialResult.first());

		// 隐式拒绝，objectName="obj2"
		Pair<Integer, String> initialResult2 = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(403 == initialResult2.first());

		String policyName2 = "allowPutPolicy";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		// 显示拒绝
		Pair<Integer, String> initialResult3 = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == initialResult3.first());

		// 策略2显示允许，objectName="obj2"
		Pair<Integer, String> initialResult4 = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(200 == initialResult4.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void initialPart_deny_notAction_resource_test() {
		String policyName = "initialDenyNotAction", policyName2 = "allowPolicy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == initialResult.first());

		// 显示允许PutObject 对test01/* 的操作
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> initialResult2 = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == initialResult2.first());
		Pair<Integer, String> initialResult3 = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(200 == initialResult3.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void initialPart_deny_notAction_notResource_test() {
		String policyName = "initialDenyNotAction", policyName2 = "allowPolicy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		// 隐式拒绝
		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == initialResult.first());

		// 显示拒绝，objectName="obj2"
		Pair<Integer, String> initialResult2 = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(403 == initialResult2.first());

		// 显示允许PutObject 对test01/* 的操作
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> initialResult3 = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult3.first());
		Pair<Integer, String> initialResult4 = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName2, new HashMap<String, String>());
		assertTrue(403 == initialResult4.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void initialPart_twoStat_match_test() {
		String policyName = "initial2StatMatch", policyName2 = "allowPolicy";
		List<Statement> statements = new ArrayList<Statement>();
		Statement s1 = IAMTestUtils.CreateStatement(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		statements.add(s1);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		Statement s2 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "Action", Arrays.asList("oos:PutObject"),
				"Resource", Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		statements.add(s2);
		String policyString = IAMTestUtils.CreateMoreStatement(statements);

		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void initialPart_twoStat_notMatch_test() {
		String policyName = "initial2StatNotMatch";
		List<Statement> statements = new ArrayList<Statement>();
		Statement s1 = IAMTestUtils.CreateStatement(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		statements.add(s1);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		Statement s2 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "Action", Arrays.asList("oos:GetObject"),
				"Resource", Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		statements.add(s2);
		String policyString = IAMTestUtils.CreateMoreStatement(statements);

		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(403 == initialResult.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void uploadPart_allow_action_notResource_test() {
		String policyName1 = "resourcePolicy", policyName2 = "notResourcePolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(403 == uploadPartResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void uploadPart_allow_notAction_test() {
		String policyName1 = "notActionPolicy", policyName2 = "actionPolicy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy2
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(403 == uploadPartResult.first());
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> uploadPartResult2 = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void uploadPart_allow_notAction_notResource_test() {
		String policyName1 = "notActionPolicy", policyName2 = "actionPolicy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(403 == uploadPartResult.first());
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> uploadPartResult2 = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void uploadPart_deny_action_bucketName_test() {
		String policyName1 = "denyPolicy", policyName2 = "alowPolicy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy2
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// 同时有allow和deny，最终拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(403 == uploadPartResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void uploadPart_deny_action_objectName_test() {
		String policyName1 = "denyPolicy", policyName2 = "alowPolicy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy2
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// 同时有allow和deny，最终拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(403 == uploadPartResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void uploadPart_deny_notAction_bucketName_test() {
		String policyName1 = "denyPolicy", policyName2 = "alowPolicy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy2
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// 同时有allow和deny，最终拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(403 == uploadPartResult.first());
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> uploadPartResult2 = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void uploadPart_deny_notAction_objectName_test() {
		String policyName1 = "denyPolicy", policyName2 = "alowPolicy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy2
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// 同时有allow和deny，最终拒绝
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(403 == uploadPartResult.first());
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> uploadPartResult2 = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void uploadPart_deny_notAction_notResource_test() {
		String policyName1 = "denyPolicy", policyName2 = "alowPolicy", policyName3 = "alowPolicy2";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp", Arrays.asList("127.0.0.1")));
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		String policyString3 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName2), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3, 200);
		// 给用户添加policy2
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName3, 200);
		Pair<Integer, String> uploadPartResult2 = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(403 == uploadPartResult2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName3, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName3, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void uploadPart_deny_Action_twoStat_notMatch_test() {
		String policyName = "twostatPolicy", policyName1 = "allowPolicy";
		List<Statement> statements = new ArrayList<Statement>();
		Statement s1 = IAMTestUtils.CreateStatement(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		statements.add(s1);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		Statement s2 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "Action", Arrays.asList("oos:PutObject"),
				"Resource", Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		statements.add(s2);
		String policyString = IAMTestUtils.CreateMoreStatement(statements);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);

		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> uploadPartResult2 = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(403 == uploadPartResult2.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void listParts_allow_action_all_test() {
		String policyName = "resourcePolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void listParts_allow_action_bucketName_test() {
		String policyName = "resourcePolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void listParts_allow_action_objectName_test() {
		String policyName = "policy1", policyName2 = "policy2";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName2), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(403 == listPartsResult.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void listParts_allow_action_notResource_test() {
		String policyName = "policy1", policyName2 = "policy2";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:ListMultipartUploadParts"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(403 == listPartsResult.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void listParts_allow_notAction_test() {
		String policyName = "policy1", policyName2 = "policy2";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(403 == listPartsResult.first());
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> listPartsResult2 = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult2.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void listParts_deny_action_bucketName_test() {
		String policyName = "policy1", policyName2 = "policy2";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> listPartsResult2 = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(403 == listPartsResult2.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void listParts_deny_action_objectName_notMatchtest() {
		String policyName = "policy1", policyName2 = "policy2";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> listPartsResult2 = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(403 == listPartsResult2.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void listParts_deny_action_objectName_match_test() {
		String policyName = "policy1", policyName2 = "policy2";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName2), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> listPartsResult2 = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult2.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void listParts_deny_notAction_test() {
		String policyName = "policy1", policyName2 = "policy2";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> listPartsResult2 = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(403 == listPartsResult2.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void listParts_deny_notAction_notResource_notMatch_test() {
		String policyName = "policy1", policyName2 = "policy2";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName2), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> listPartsResult2 = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(403 == listPartsResult2.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void listParts_deny_notAction_notResource_match_test() {
		String policyName = "policy1", policyName2 = "policy2";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> listPartsResult2 = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult2.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void listParts_twoStat_test() {
		String policyName = "policy1", policyName2 = "policy2";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		List<Statement> statements = new ArrayList<Statement>();
		Statement s1 = IAMTestUtils.CreateStatement(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:DeleteObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		statements.add(s1);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		Statement s2 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "Action", Arrays.asList("oos:PutObject"),
				"Resource", Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		statements.add(s2);
		String policyString = IAMTestUtils.CreateMoreStatement(statements);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> listPartsResult2 = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(403 == listPartsResult2.first());
		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@Test
	public void abort_allow_action_test() {
		String policyName = "abort_allow_Policy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:AbortMultipartUpload", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Pair<Integer, String> abortResult = OOSInterfaceTestUtils.object_AbortMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(204 == abortResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(404 == listPartsResult.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	public void abort_allow_action_notResource_test() {
		String policyName = "abort_allow_Policy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:AbortMultipartUpload", "oos:ListMultipartUploadParts"),
				"NotResource", Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName2),
				null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Pair<Integer, String> abortResult = OOSInterfaceTestUtils.object_AbortMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(204 == abortResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(404 == listPartsResult.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	public void abort_allow_notAction_test() {
		String policyName = "abort_allow_Policy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Pair<Integer, String> abortResult = OOSInterfaceTestUtils.object_AbortMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(204 == abortResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(404 == listPartsResult.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	public void abort_allow_notAction_notResource_test() {
		String policyName = "abort_notAction_notResource_Policy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName2), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Pair<Integer, String> abortResult = OOSInterfaceTestUtils.object_AbortMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(204 == abortResult.first());
		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(404 == listPartsResult.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	public void abort_deny_action_test() {
		String policyName = "allow_action_Policy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());

		String policyName2 = "abort_deny_action";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:AbortMultipartUpload"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> abortResult = OOSInterfaceTestUtils.object_AbortMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(403 == abortResult.first());

		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(200 == listPartsResult.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@Test
	public void abort_deny_notAction_test() {
		String policyName = "allow_action_Policy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts", "oos:AbortMultipartUpload"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());

		String policyName2 = "abort_deny_notAction";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:AbortMultipartUpload"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> abortResult = OOSInterfaceTestUtils.object_AbortMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(204 == abortResult.first());

		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(403 == listPartsResult.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@Test
	public void abort_deny_notAction_notResource_test() {
		String policyName = "allow_action_Policy";
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:ListMultipartUploadParts", "oos:AbortMultipartUpload"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "clientContent", new HashMap());
		assertTrue(200 == uploadPartResult.first());

		String policyName2 = "abort_deny_notAction_notResource";
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:AbortMultipartUpload"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Pair<Integer, String> abortResult = OOSInterfaceTestUtils.object_AbortMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(204 == abortResult.first());

		Pair<Integer, String> listPartsResult = OOSInterfaceTestUtils.Object_ListPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, new HashMap());
		assertTrue(404 == listPartsResult.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void complete_allow_action_notResource_test() {
		String policyName1 = "allowPolicy", policyName2 = "denyPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "aaaaaaa", new HashMap());
		assertTrue(200 == uploadPartResult.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		Map<String, String> partEtagMap = new HashMap<String, String>();
		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(403 == completeResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	/**
	 * 合并片段 策略一测试NotAction,显示允许 resource匹配
	 */
	@SuppressWarnings("unchecked")
	@Test
	public void complete_allow_notAction_bucketName_test() {
		String policyName = "notActionPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString1, 200);
		// 给用户添加policy1
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "client message", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Map<String, String> partEtagMap = new HashMap<String, String>();

		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(200 == completeResult.first()); // 显示允许

		Pair<Integer, String> delete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap());
		assertTrue(204 == delete.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void complete_allow_notAction_objectName_test() {
		String policyName1 = "notActionPolicy", policyName2 = "actionPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy1
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "aaaaaaa", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Map<String, String> partEtagMap = new HashMap<String, String>();

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(403 == completeResult.first()); // 隐式拒绝

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void complete_allow_notAction_notResource_notMatch_test() {
		String policyName1 = "notActionPolicy", policyName2 = "actionPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:PutObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy1
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "aaaaaaa", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Map<String, String> partEtagMap = new HashMap<String, String>();

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(403 == completeResult.first()); // 隐式拒绝

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void complete_allow_notAction_notResource_match_test() {
		String policyName1 = "notActionPolicy", policyName2 = "actionPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "NotAction",
				Arrays.asList("oos:DeleteObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName2), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy1
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "client message", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Map<String, String> partEtagMap = new HashMap<String, String>();

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(200 == completeResult.first()); // 隐式拒绝

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void complete_deny_action_bucketName_test() {
		String policyName1 = "allowPolicy", policyName2 = "denyPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy1
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "client message", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Map<String, String> partEtagMap = new HashMap<String, String>();

		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(403 == completeResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void complete_deny_action_objectName_test() {
		String policyName1 = "allowPolicy", policyName2 = "denyPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName2), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy1
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "client message", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Map<String, String> partEtagMap = new HashMap<String, String>();

		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(200 == completeResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void complete_deny_notAction_bucketName_test() {
		String policyName1 = "allowPolicy", policyName2 = "denyPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy1
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "client message", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Map<String, String> partEtagMap = new HashMap<String, String>();

		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(403 == completeResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void complete_deny_notAction_objectName_test() {
		String policyName1 = "allowPolicy", policyName2 = "denyPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName2), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy1
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "client message", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Map<String, String> partEtagMap = new HashMap<String, String>();

		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(200 == completeResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void complete_deny_notAction_notResource_test() {
		String policyName1 = "allowPolicy", policyName2 = "denyPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "NotAction",
				Arrays.asList("oos:GetObject"), "NotResource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName2), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy1
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "aaaaaaa", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Map<String, String> partEtagMap = new HashMap<String, String>();

		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(403 == completeResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void complete_allow_twoStat_test() {
		String policyName1 = "allowPolicy", policyName2 = "denyPolicy";
		String policyString1 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), null);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName1, policyString1, 200);
		List<Statement> statements = new ArrayList<Statement>();
		Statement s1 = IAMTestUtils.CreateStatement(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/" + objectName), null);
		statements.add(s1);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		Statement s2 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "Action", Arrays.asList("oos:PutObject"),
				"Resource", Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		statements.add(s2);
		String policyString = IAMTestUtils.CreateMoreStatement(statements);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString, 200);
		// 给用户添加policy1
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);

		Pair<Integer, String> initialResult = OOSInterfaceTestUtils.Object_InitialMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, new HashMap<String, String>());
		assertTrue(200 == initialResult.first());
		String initialXml = initialResult.second();
		StringReader sr = new StringReader(initialXml);
		InputSource is = new InputSource(sr);
		Document doc;
		String uploadId = "";
		try {
			doc = (new SAXBuilder()).build(is);
			Element root = doc.getRootElement();
			@SuppressWarnings("unchecked")
			List<Element> secondLevel = root.getChildren();
			uploadId = secondLevel.get(2).getText();
			System.out.println(uploadId);
		} catch (Exception e) {
			e.printStackTrace();
		}

		Pair<Integer, String> uploadPartResult = OOSInterfaceTestUtils.Object_UploadPart(http, signVersion, jettyPort,
				user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, 1, "aaaaaaa", new HashMap());
		assertTrue(200 == uploadPartResult.first());
		Map<String, String> partEtagMap = new HashMap<String, String>();

		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		partEtagMap.put("1", uploadPartResult.second());
		Pair<Integer, String> completeResult = OOSInterfaceTestUtils.Object_CompleteMultipartUpload(http, signVersion,
				jettyPort, user1accessKey1, user1secretKey1, bucketName, objectName, uploadId, partEtagMap,
				new HashMap());
		assertTrue(403 == completeResult.first());

		// 用户解除策略,删除策略
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName1, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName1, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@Test
	public void condition_userid_StringEquals_test() {
		String policyName = "useridStringEquals_test";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals", "ctyun:userid", Arrays.asList("test1abc")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put.first());
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put2.first());
		
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}


	@Test
	public void condition_userName_StringEquals_test() {
		String policyName = "StringEquals_test";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals", "ctyun:username", Arrays.asList("test_2")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put.first());
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put2.first());
		
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}
	
	
	@Test
	public void condition_UserAgent_StringEquals_test() {
		String policyName = "UserAgentStringEquals_test";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals", "ctyun:UserAgent", Arrays.asList("Java/1.8.0_121")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		HashMap<String, String> map = new HashMap<String, String>();
		map.put("User-Agent", "Java/1.7.0");
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", map);
		assertTrue(403 == put.first());

		map.put("User-Agent", "Java/1.8.0_121");
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", map);
		assertTrue(200 == put2.first());
		
		Pair<Integer, String> rootDelete = OOSInterfaceTestUtils.Object_Delete(http, signVersion, jettyPort, accessKey,
				secretKey, bucketName, objectName, new HashMap<String, String>());
		assertTrue(204 == rootDelete.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	public void condition_Referer_StringEquals_test() {
		String policyName = "RefererStringEquals_test";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals", "ctyun:Referer",
				Arrays.asList("http://www.yourwebsitename.com/login.html")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		HashMap<String, String> map = new HashMap<String, String>();
		map.put("Referer", "http://www.yourwebsitename.com/Login.html");
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", map);
		assertTrue(403 == put.first());

		map.put("Referer", "http://www.yourwebsitename.com/console.html");
		Pair<Integer, String> put1 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", map);
		assertTrue(403 == put1.first());

		map.put("Referer", "http://www.yourwebsitename.com/login.html");
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", map);
		assertTrue(200 == put2.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/**
	 * 多个condition,一个statement，一个policy
	 */
	@Test
	public void condition_more_test() {
		String policyName = "moreConditionsEquals_test";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals", "ctyun:Referer",
				Arrays.asList("http://www.yourwebsitename.com/login.html")));
		conditions.add(IAMTestUtils.CreateCondition("StringEquals", "ctyun:UserAgent", Arrays.asList("Java/1.8.0")));
		conditions
				.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase", "ctyun:userid", Arrays.asList("test1abc")));
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);

		HashMap<String, String> map = new HashMap<String, String>();
		map.put("Referer", "http://www.yourwebsitename.com/login.html");
		map.put("User-Agent", "Java/1.8.0");
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", map);
		assertTrue(200 == put.first());

		map.put("Referer", "http://www.yourwebsitename.com/login.html");
		map.put("User-Agent", "Java/1.8.0");
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", map);
		assertTrue(200 == put2.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/**
	 * 多个condition,两个statement，一个policy
	 */
	@Test
	public void condition_more_twoStat_test() {
		String policyName = "moreConditions_twoStat_test";
		List<Statement> statements = new ArrayList<Statement>();
		List<Condition> conditions1 = new ArrayList<Condition>();
		conditions1.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		conditions1.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase", "ctyun:Referer",
				Arrays.asList("http://www.yourwebsitename.com/login.html")));
		Statement s1 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions1);
		statements.add(s1);
		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals", "ctyun:userid", Arrays.asList("test1abc")));
		conditions2
				.add(IAMTestUtils.CreateCondition("StringEquals", "ctyun:UserAgent", Arrays.asList("Java/1.8.0_121")));
		Statement s2 = IAMTestUtils.CreateStatement(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions2);
		statements.add(s2);
		String policyString = IAMTestUtils.CreateMoreStatement(statements);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		HashMap<String, String> map = new HashMap<String, String>();
		map.put("Referer", "http://www.yourwebsitename.com/login.html");
		map.put("User-Agent", "Java/1.8.0_121");
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", map);
		assertTrue(200 == put.first());

		map.put("Referer", "http://www.yourwebsitename.com/login.html");
		map.put("User-Agent", "Java/1.8.0_121");
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", map);
		assertTrue(403 == put2.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	/**
	 * 多个condition,多个statement，2个policy
	 */
	@Test
	public void condition_more_twoStat_twoPolicy_test() {
		String policyName = "moreConditions_twoStat_test";
		List<Statement> statements = new ArrayList<Statement>();
		List<Condition> conditions1 = new ArrayList<Condition>();
		conditions1.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		conditions1.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase", "ctyun:Referer",
				Arrays.asList("http://www.yourwebsitename.com/login.html")));
		Statement s1 = IAMTestUtils.CreateStatement(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions1);
		statements.add(s1);
		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals", "ctyun:userid", Arrays.asList("test1abc")));
		conditions2
				.add(IAMTestUtils.CreateCondition("StringEquals", "ctyun:UserAgent", Arrays.asList("Java/1.8.0_121")));
		Statement s2 = IAMTestUtils.CreateStatement(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions2);
		statements.add(s2);
		String policyString = IAMTestUtils.CreateMoreStatement(statements);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		String policyName2 = "denyPolicy";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp",
				Arrays.asList("192.168.1.1/24", "192.168.3.1")));
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny, null, null, "Action",
				Arrays.asList("oos:PutObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);

		HashMap<String, String> map = new HashMap<String, String>();
		map.put("Referer", "http://www.yourwebsitename.com/login.html");
		map.put("User-Agent", "Java/1.8.0_121");
		map.put("X-Forwarded-For", "192.168.1.101");
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", map);
		assertTrue(403 == put.first());

		map.put("Referer", "http://www.yourwebsitename.com/login.html");
		map.put("User-Agent", "Java/1.8.0_121");
		map.put("X-Forwarded-For", "192.168.3.2");
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", map);
		assertTrue(403 == put2.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@Test
	public void condition_StringNotEquals_test() {
		String policyName = "StringNotEquals_test";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEquals", "ctyun:username", Arrays.asList("test_2")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put.first());
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put2.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	public void condition_StringEqualsIgnoreCase_test() {
		String policyName = "StringEqualsIgnoreCase_test";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions
				.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase", "ctyun:userid", Arrays.asList("test1abc")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		// 给用户添加policy
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put.first());
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put2.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	public void condition_StringNotEqualsIgnoreCase_test() {
		String policyName = "StringNotEqualsIgnoreCase_test";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(
				IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase", "ctyun:userid", Arrays.asList("Test1Abc")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put.first());
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put2.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	public void condition_StringLike_test() {
		String policyName = "StringLike_test";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike", "ctyun:username", Arrays.asList("test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put.first());
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put2.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	public void condition_StringNotLike_test() {
		String policyName = "StringNotLike_test";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotLike", "ctyun:username", Arrays.asList("test*")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);

		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put.first());
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put2.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	public void condition_CurrentTime_DateEquals_test() {
		String policyName = "CurrentTime_DateEquals_test1";
		String yesterdayString = OneDay0UTCTimeString(-1);
		String todyString = OneDay0UTCTimeString(0);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateEquals", "ctyun:CurrentTime", Arrays.asList(yesterdayString)));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put.first());

		String policyName2 = "CurrentTime_DateEquals_test2";
		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateEquals", "ctyun:CurrentTime", Arrays.asList(todyString)));
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put2.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@Test
	public void condition_CurrentTime_DateNotEquals_test() {
		String policyName = "CurrentTime_DateNotEquals_test1";
		String yesterdayString = OneDay0UTCTimeString(-1);
		String todyString = OneDay0UTCTimeString(0);
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(
				IAMTestUtils.CreateCondition("DateNotEquals", "ctyun:CurrentTime", Arrays.asList(yesterdayString)));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put.first());

		String policyName2 = "CurrentTime_DateNotEquals_test2";
		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateNotEquals", "ctyun:CurrentTime", Arrays.asList(todyString)));
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put2.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
	}

	@Test
	public void condition_CurrentTime_DateLessThan_test() {
		String yesterdayString = OneDay0UTCTimeString(-1);
		String todyString = OneDay0UTCTimeString(0);
		String tomorrowString = OneDay0UTCTimeString(1);

		String policyName = "CurrentTime_DateLessThan_test1";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions
				.add(IAMTestUtils.CreateCondition("DateLessThan", "ctyun:CurrentTime", Arrays.asList(yesterdayString)));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put.first());

		String policyName2 = "CurrentTime_DateNotEquals_test2";
		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateNotEquals", "ctyun:CurrentTime", Arrays.asList(todyString)));
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put2.first());

		String policyName3 = "CurrentTime_DateNotEquals_test3";
		List<Condition> conditions3 = new ArrayList<Condition>();
		conditions3
				.add(IAMTestUtils.CreateCondition("DateNotEquals", "ctyun:CurrentTime", Arrays.asList(tomorrowString)));
		String policyString3 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions3);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
		Pair<Integer, String> put3 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user3accessKey,
				user3secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put3.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName3, 200);
	}

	@Test
	public void condition_CurrentTime_DateLessThanEquals_test() {
		String yesterdayString = OneDay0UTCTimeString(-1);
		String todyString = OneDay0UTCTimeString(0);
		String tomorrowString = OneDay0UTCTimeString(1);

		String policyName = "CurrentTime_DateLessThanEquals_test1";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateLessThanEquals", "ctyun:CurrentTime",
				Arrays.asList(yesterdayString)));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put.first());

		String policyName2 = "CurrentTime_DateLessThanEquals_test2";
		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(
				IAMTestUtils.CreateCondition("DateLessThanEquals", "ctyun:CurrentTime", Arrays.asList(todyString)));
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put2.first());

		String policyName3 = "CurrentTime_DateLessThanEquals_test3";
		List<Condition> conditions3 = new ArrayList<Condition>();
		conditions3.add(
				IAMTestUtils.CreateCondition("DateLessThanEquals", "ctyun:CurrentTime", Arrays.asList(tomorrowString)));
		String policyString3 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions3);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
		Pair<Integer, String> put3 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user3accessKey,
				user3secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put3.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName3, 200);
	}

	@Test
	public void condition_CurrentTime_DateGreaterThan_test() {
		String yesterdayString = OneDay0UTCTimeString(-1);
		String todyString = OneDay0UTCTimeString(0);
		String tomorrowString = OneDay0UTCTimeString(1);

		String policyName = "CurrentTime_DateGreaterThan_test1";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(
				IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime", Arrays.asList(yesterdayString)));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put.first());

		String policyName2 = "CurrentTime_DateGreaterThan_test2";
		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2
				.add(IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime", Arrays.asList(todyString)));
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put2.first());

		String policyName3 = "CurrentTime_DateGreaterThan_test3";
		List<Condition> conditions3 = new ArrayList<Condition>();
		conditions3.add(
				IAMTestUtils.CreateCondition("DateGreaterThan", "ctyun:CurrentTime", Arrays.asList(tomorrowString)));
		String policyString3 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions3);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
		Pair<Integer, String> put3 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user3accessKey,
				user3secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put3.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName3, 200);
	}

	@Test
	public void condition_CurrentTime_DateGreaterThanEquals_test() {
		String yesterdayString = OneDay0UTCTimeString(-1);
		String todyString = OneDay0UTCTimeString(0);
		String tomorrowString = OneDay0UTCTimeString(1);

		String policyName = "CurrentTime_DateGreaterThanEquals_test1";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThanEquals", "ctyun:CurrentTime",
				Arrays.asList(yesterdayString)));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put.first());

		String policyName2 = "CurrentTime_DateGreaterThanEquals_test2";
		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(
				IAMTestUtils.CreateCondition("DateGreaterThanEquals", "ctyun:CurrentTime", Arrays.asList(todyString)));
		String policyString2 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions2);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user2accessKey,
				user2secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put2.first());

		String policyName3 = "CurrentTime_DateGreaterThanEquals_test3";
		List<Condition> conditions3 = new ArrayList<Condition>();
		conditions3.add(IAMTestUtils.CreateCondition("DateGreaterThanEquals", "ctyun:CurrentTime",
				Arrays.asList(tomorrowString)));
		String policyString3 = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions3);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName3, policyString3, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
		Pair<Integer, String> put3 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user3accessKey,
				user3secretKey, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put3.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user3Name, policyName3, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName3, 200);
	}

	@Test
	public void condition_SecureTransport_false_test() {
		String policyName = "CurrentTime_SecureTransport_false";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("false")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put("http", signVersion, 8080, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put.first());

		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put("https", signVersion, 8443, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put2.first());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	public void condition_SecureTransport_true_test() {
		String policyName = "CurrentTime_DateGreaterThanEquals_test1";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("Bool", "ctyun:SecureTransport", Arrays.asList("true")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put("http", signVersion, 8080, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(403 == put.first());

		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put("https", signVersion, 8443, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", new HashMap());
		assertTrue(200 == put2.first());
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	public void condition_SourceIp_IpAddress_test() {
		String policyName = "allowspecialIP";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("IpAddress", "ctyun:SourceIp",
				Arrays.asList("192.168.1.1/24", "192.168.3.1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("X-Forwarded-For", "192.168.2.101");
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", map);
		assertTrue(403 == put.first());

		map.put("X-Forwarded-For", "192.168.3.1");
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", map);
		assertTrue(200 == put2.first());
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	public void condition_SourceIp_NotIpAddress_test() {
		String policyName = "NotIpAddress_test";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("NotIpAddress", "ctyun:SourceIp",
				Arrays.asList("192.168.1.1/24", "192.168.3.1")));
		String policyString = IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow, null, null, "Action",
				Arrays.asList("oos:PutObject", "oos:GetObject", "oos:DeleteObject"), "Resource",
				Arrays.asList("arn:ctyun:oos::" + accountId + ":" + bucketName + "/*"), conditions);
		IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("X-Forwarded-For", "192.168.2.101");
		Pair<Integer, String> put = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", map);
		assertTrue(200 == put.first());

		map.put("X-Forwarded-For", "192.168.3.1");
		Pair<Integer, String> put2 = OOSInterfaceTestUtils.Object_Put(http, signVersion, jettyPort, user1accessKey1,
				user1secretKey1, bucketName, objectName, "helloworld", map);
		assertTrue(403 == put2.first());
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
	}

	@Test
	public void test() {
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user1Name,
				"useridstringequals_test", 200);
//		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user2Name, "CurrentTime_DateGreaterThan_test2", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "useridstringequals_test", 200);
//		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "CurrentTime_DateGreaterThan_test2", 200);

	}

//	@BeforeClass
	public static void setUp() throws Exception {
		IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
		IAMTestUtils.TrancateTable(IAMTestUtils.iamGroupTable);
		IAMTestUtils.TrancateTable(IAMTestUtils.iammfaDeviceTable);
		IAMTestUtils.TrancateTable(IAMTestUtils.iamUserTable);
//
//		String groupName = mygroupName;
//		IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
//		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user1Name, 200);
//		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, user3Name, 200);
	}

//	@Before
	@Test
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

	/*
	 * 生成yyyy-MM-dd'T'HH:mm:ss'Z'格式的字符串 参数为相对今天的偏移量，0为今天，-1为昨天，1为明天以此类推
	 */
	public static String OneDay0UTCTimeString(int offset) {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.DATE, offset);
		calendar.set(Calendar.HOUR_OF_DAY, 0);
		calendar.set(Calendar.MINUTE, 0);
		calendar.set(Calendar.SECOND, 0);
		Date date = calendar.getTime();
		String dayString = dateFormat.format(date);
		System.out.println(dayString);
		return dayString;
	}

}
