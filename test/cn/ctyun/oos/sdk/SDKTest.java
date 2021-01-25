package cn.ctyun.oos.sdk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.Protocol;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.policy.Policy;
import com.amazonaws.internal.SdkInternalList;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient;
import com.amazonaws.services.identitymanagement.model.AccessKey;
import com.amazonaws.services.identitymanagement.model.AccessKeyMetadata;
import com.amazonaws.services.identitymanagement.model.AddUserToGroupRequest;
import com.amazonaws.services.identitymanagement.model.AttachGroupPolicyRequest;
import com.amazonaws.services.identitymanagement.model.AttachGroupPolicyResult;
import com.amazonaws.services.identitymanagement.model.AttachUserPolicyRequest;
import com.amazonaws.services.identitymanagement.model.AttachedPolicy;
import com.amazonaws.services.identitymanagement.model.ChangePasswordRequest;
import com.amazonaws.services.identitymanagement.model.CreateAccessKeyRequest;
import com.amazonaws.services.identitymanagement.model.CreateAccessKeyResult;
import com.amazonaws.services.identitymanagement.model.CreateGroupRequest;
import com.amazonaws.services.identitymanagement.model.CreateGroupResult;
import com.amazonaws.services.identitymanagement.model.CreateLoginProfileRequest;
import com.amazonaws.services.identitymanagement.model.CreateLoginProfileResult;
import com.amazonaws.services.identitymanagement.model.CreatePolicyRequest;
import com.amazonaws.services.identitymanagement.model.CreatePolicyResult;
import com.amazonaws.services.identitymanagement.model.CreateUserRequest;
import com.amazonaws.services.identitymanagement.model.CreateUserResult;
import com.amazonaws.services.identitymanagement.model.CreateVirtualMFADeviceRequest;
import com.amazonaws.services.identitymanagement.model.CreateVirtualMFADeviceResult;
import com.amazonaws.services.identitymanagement.model.DeactivateMFADeviceRequest;
import com.amazonaws.services.identitymanagement.model.DeleteAccessKeyRequest;
import com.amazonaws.services.identitymanagement.model.DeleteAccountPasswordPolicyRequest;
import com.amazonaws.services.identitymanagement.model.DeleteGroupRequest;
import com.amazonaws.services.identitymanagement.model.DeleteLoginProfileRequest;
import com.amazonaws.services.identitymanagement.model.DeletePolicyRequest;
import com.amazonaws.services.identitymanagement.model.DeleteUserRequest;
import com.amazonaws.services.identitymanagement.model.DeleteVirtualMFADeviceRequest;
import com.amazonaws.services.identitymanagement.model.DetachGroupPolicyRequest;
import com.amazonaws.services.identitymanagement.model.DetachUserPolicyRequest;
import com.amazonaws.services.identitymanagement.model.EnableMFADeviceRequest;
import com.amazonaws.services.identitymanagement.model.GetAccountPasswordPolicyRequest;
import com.amazonaws.services.identitymanagement.model.GetAccountPasswordPolicyResult;
import com.amazonaws.services.identitymanagement.model.GetAccountSummaryRequest;
import com.amazonaws.services.identitymanagement.model.GetAccountSummaryResult;
import com.amazonaws.services.identitymanagement.model.GetGroupRequest;
import com.amazonaws.services.identitymanagement.model.GetGroupResult;
import com.amazonaws.services.identitymanagement.model.GetLoginProfileRequest;
import com.amazonaws.services.identitymanagement.model.GetLoginProfileResult;
import com.amazonaws.services.identitymanagement.model.GetPolicyRequest;
import com.amazonaws.services.identitymanagement.model.GetPolicyResult;
import com.amazonaws.services.identitymanagement.model.GetUserRequest;
import com.amazonaws.services.identitymanagement.model.GetUserResult;
import com.amazonaws.services.identitymanagement.model.GroupResult;
import com.amazonaws.services.identitymanagement.model.ListAccessKeysRequest;
import com.amazonaws.services.identitymanagement.model.ListAccessKeysResult;
import com.amazonaws.services.identitymanagement.model.ListAttachedGroupPoliciesRequest;
import com.amazonaws.services.identitymanagement.model.ListAttachedGroupPoliciesResult;
import com.amazonaws.services.identitymanagement.model.ListAttachedUserPoliciesRequest;
import com.amazonaws.services.identitymanagement.model.ListAttachedUserPoliciesResult;
import com.amazonaws.services.identitymanagement.model.ListEntitiesForPolicyRequest;
import com.amazonaws.services.identitymanagement.model.ListEntitiesForPolicyResult;
import com.amazonaws.services.identitymanagement.model.ListGroupsForUserRequest;
import com.amazonaws.services.identitymanagement.model.ListGroupsForUserResult;
import com.amazonaws.services.identitymanagement.model.ListGroupsRequest;
import com.amazonaws.services.identitymanagement.model.ListGroupsResult;
import com.amazonaws.services.identitymanagement.model.ListMFADevicesRequest;
import com.amazonaws.services.identitymanagement.model.ListMFADevicesResult;
import com.amazonaws.services.identitymanagement.model.ListPoliciesRequest;
import com.amazonaws.services.identitymanagement.model.ListPoliciesResult;
import com.amazonaws.services.identitymanagement.model.ListUserTagsRequest;
import com.amazonaws.services.identitymanagement.model.ListUserTagsResult;
import com.amazonaws.services.identitymanagement.model.ListUsersRequest;
import com.amazonaws.services.identitymanagement.model.ListUsersResult;
import com.amazonaws.services.identitymanagement.model.ListVirtualMFADevicesRequest;
import com.amazonaws.services.identitymanagement.model.ListVirtualMFADevicesResult;
import com.amazonaws.services.identitymanagement.model.LoginProfile;
import com.amazonaws.services.identitymanagement.model.MFADevice;
import com.amazonaws.services.identitymanagement.model.PasswordPolicy;
import com.amazonaws.services.identitymanagement.model.PolicyGroup;
import com.amazonaws.services.identitymanagement.model.PolicyUser;
import com.amazonaws.services.identitymanagement.model.RemoveUserFromGroupRequest;
import com.amazonaws.services.identitymanagement.model.Tag;
import com.amazonaws.services.identitymanagement.model.TagUserRequest;
import com.amazonaws.services.identitymanagement.model.UntagUserRequest;
import com.amazonaws.services.identitymanagement.model.UpdateAccessKeyRequest;
import com.amazonaws.services.identitymanagement.model.UpdateAccountPasswordPolicyRequest;
import com.amazonaws.services.identitymanagement.model.UpdateLoginProfileRequest;
import com.amazonaws.services.identitymanagement.model.User;
import com.amazonaws.services.identitymanagement.model.UserResult;
import com.amazonaws.services.identitymanagement.model.VirtualMFADevice;
import com.amazonaws.services.s3.model.AmazonS3Exception;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.server.entity.AccountSummary;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.service.AccountSummaryService;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class SDKTest {
	private final static String OOS_DOMAIN = "oos-loc6-iam.ctyunapi.cn:9460";
	private final static String ownerName = "root1@test.com";
	private final static String AK = "userak";
	private final static String SK = "usersk";
	private final static String ownerName2 = "root2@test.com";
	private final static String AK2 = "userak2";
	private final static String SK2 = "usersk2";
	public static String accountId = "34e5k5ig79cjf";
	public static String accountId2 = "2khdzd8yb0pkw";

	// 子用户
	private final static String subUser1 = "user1@oos.com";
	private final static String subUser2 = "user2@oos.com";
	private final static String ak1 = "user1ak";
	private final static String sk1 = "user1ak";
	private final static String ak2 = "user2ak";
	private final static String sk2 = "user2ak";

	private static ClientConfiguration config = new ClientConfiguration();
	private static AmazonIdentityManagement client;
	private static AmazonIdentityManagement client2;
	private static AmazonIdentityManagement rootClient;
	private static AmazonIdentityManagement rootClient2;
	private static OwnerMeta owner = new OwnerMeta(ownerName);
	private static OwnerMeta owner2 = new OwnerMeta(ownerName2);
	public static MetaClient metaClient = MetaClient.getGlobalClient();
	static {
		System.setProperty("com.amazonaws.sdk.disableCertChecking", "true");
		config.setProtocol(Protocol.HTTPS);
		config.setMaxErrorRetry(0);
		config.setConnectionTimeout(0);
		config.setSocketTimeout(0);
		client = new AmazonIdentityManagementClient(new AWSCredentials() {
			@Override
			public String getAWSAccessKeyId() {
				return ak1;
			}

			@Override
			public String getAWSSecretKey() {
				return sk1;
			}
		}, config);
		client.setEndpoint(OOS_DOMAIN);

		client2 = new AmazonIdentityManagementClient(new AWSCredentials() {
			@Override
			public String getAWSAccessKeyId() {
				return ak2;
			}

			@Override
			public String getAWSSecretKey() {
				return sk2;
			}
		}, config);
		client2.setEndpoint(OOS_DOMAIN);

		rootClient = new AmazonIdentityManagementClient(new AWSCredentials() {
			@Override
			public String getAWSAccessKeyId() {
				return AK;
			}

			@Override
			public String getAWSSecretKey() {
				return SK;
			}
		}, config);
		rootClient.setEndpoint(OOS_DOMAIN);

		rootClient2 = new AmazonIdentityManagementClient(new AWSCredentials() {
			@Override
			public String getAWSAccessKeyId() {
				return AK2;
			}

			@Override
			public String getAWSSecretKey() {
				return SK2;
			}
		}, config);
		rootClient2.setEndpoint(OOS_DOMAIN);

	}

	@BeforeClass
//	@Test
	public  void setUpBeforeClass() throws Exception {
		IAMTestUtils.TrancateTable("iam-policy-wtz");
		IAMTestUtils.TrancateTable("oos-aksk-wtz2");
		IAMTestUtils.TrancateTable("oos-owner-wtz");
		IAMTestUtils.TrancateTable("iam-user-wtz");
		IAMTestUtils.TrancateTable("iam-accountSummary-wtz");
		IAMTestUtils.TrancateTable("iam-mfaDevice-wtz");

		MetaClient metaClient = MetaClient.getGlobalClient();
		// 创建根用户1
		owner.email = ownerName;
		owner.setPwd("123456");
		owner.maxAKNum = 10;
		owner.displayName = "测试根用户1";
		owner.bucketCeilingNum = 10;
		metaClient.ownerInsertForTest(owner);

		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.accessKey = AK;
		aksk.setSecretKey(SK);
		aksk.isPrimary = 1;
		metaClient.akskInsert(aksk);

		// 创建根用户2
		owner2.email = ownerName2;
		owner2.setPwd("123456");
		owner2.maxAKNum = 10;
		owner2.displayName = "测试根用户2";
		owner2.bucketCeilingNum = 10;
		metaClient.ownerInsertForTest(owner2);

		AkSkMeta aksk2 = new AkSkMeta(owner2.getId());
		aksk2.accessKey = AK2;
		aksk2.setSecretKey(SK2);
		aksk2.isPrimary = 1;
		metaClient.akskInsert(aksk2);
		// 创建子用户
		// 创建subUser1
		cn.ctyun.oos.iam.server.entity.User user1 = new cn.ctyun.oos.iam.server.entity.User();
		user1.accountId = accountId;
		user1.userName = subUser1;
		user1.userId = "Test1Abc";
		user1.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user1);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta subAksk = new AkSkMeta(owner.getId());
		subAksk.isRoot = 0;
		subAksk.userId = user1.userId;
		subAksk.userName = subUser1;
		subAksk.accessKey = ak1;
		subAksk.setSecretKey(sk1);
		metaClient.akskInsert(subAksk);
		user1.accessKeys = new ArrayList<>();
		user1.userName = subUser1;
		user1.accessKeys.add(subAksk.accessKey);
		HBaseUtils.put(user1);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1
		// 创建subUser2
		cn.ctyun.oos.iam.server.entity.User user2 = new cn.ctyun.oos.iam.server.entity.User();
		user2.accountId = accountId2;
		user2.userName = subUser2;
		user2.userId = "test2Abc";
		user2.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user2);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}
		AkSkMeta subAksk2 = new AkSkMeta(owner2.getId());
		subAksk2.isRoot = 0;
		subAksk2.userId = user2.userId;
		subAksk2.userName = subUser2;
		subAksk2.accessKey = ak2;
		subAksk2.setSecretKey(sk2);
		metaClient.akskInsert(subAksk2);
		user2.accessKeys = new ArrayList<>();
		user2.userName = subUser2;
		user2.accessKeys.add(subAksk2.accessKey);
		HBaseUtils.put(user2);
		AccountSummaryService.increment(accountId2, AccountSummary.USERS, 1);// 账户中的用户数量加1
		// 创建策略并赋予用户
		// 创建策略
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setDescription("For Sdk Test");
		createPolicyRequest.setPolicyName("sdkPolicy");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		rootClient.createPolicy(createPolicyRequest);
		// 分配策略到用户
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		attachUserPolicyRequest.setUserName(subUser1);
		rootClient.attachUserPolicy(attachUserPolicyRequest);

		// 创建策略
		CreatePolicyRequest createPolicyRequest2 = new CreatePolicyRequest();
		createPolicyRequest2.setDescription("For Sdk Test2");
		createPolicyRequest2.setPolicyName("sdkPolicy2");
		String policyDocument2 = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924572\",\"Statement\":[{\"Sid\":\"1569805924572_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::2khdzd8yb0pkw:*\"}]}";
		createPolicyRequest2.setPolicyDocument(policyDocument2);
		rootClient2.createPolicy(createPolicyRequest2);
		// 分配策略到用户
		AttachUserPolicyRequest attachUserPolicyRequest2 = new AttachUserPolicyRequest();
		attachUserPolicyRequest2.setPolicyArn("arn:ctyun:iam::2khdzd8yb0pkw:policy/sdkPolicy2");
		attachUserPolicyRequest2.setUserName(subUser2);
		rootClient2.attachUserPolicy(attachUserPolicyRequest2);
	}

	/**
	 * 用户名在帐户中必须是唯一的。 用户名不区分大小写。所以同一账户中不能创建相同名称（大小写相同、大小写不同）的用户。
	 * 例如不能创建两个用户"TESTUSER"和"testuser"。
	 * 
	 */
	@Test
	public void createUser_sameUserName_sameAccount_fail_test() {
		String userName1 = "TESTUSER";
		String userName2 = "testuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName1);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName1, user.getUserName());
		try {
			CreateUserRequest cu2 = new CreateUserRequest();
			cu2.setUserName(userName2);
			client.createUser(cu2);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("EntityAlreadyExists", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("User with name testuser already exists.", e.getMessage());
		}
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName1);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 不能创建两个名称相同的用户"testuser"和"testuser"
	 */
	@Test
	public void createUser_sameUserName_sameAccount_fail_test2() {
		String userName1 = "testuser";
		String userName2 = "testuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName1);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName1, user.getUserName());
		try {
			CreateUserRequest cu2 = new CreateUserRequest();
			cu2.setUserName(userName2);
			client.createUser(cu2);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("EntityAlreadyExists", e.getErrorCode());
			assertEquals("User with name testuser already exists.", e.getMessage());
		}
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName1);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 用户名在帐户中必须是唯一的。 不同账户中可以创建同名的用户
	 */
	@Test
	public void createUser_sameUserName_differentAccount_ok_test() {
		String userName = "TestUser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		CreateUserRequest cu2 = new CreateUserRequest();
		cu2.setUserName(userName);
		result = client2.createUser(cu2);
		assertEquals(userName, result.getUser().getUserName());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
		client2.deleteUser(deleteUserRequest);
	}

	@Test
	public void createUser_withTag10_ok_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		for (int i = 1; i <= 10; i++) {
			Tag tag = new Tag();
			tag.setKey("key" + i);
			tag.setValue("aa");
			tags.add(tag);
		}
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 标签的N非法
	 */
	@Test
	public void createUser_withTag11_fail_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		for (int i = 1; i <= 11; i++) {
			Tag tag = new Tag();
			tag.setKey("key" + i);
			tag.setValue("aa");
			tags.add(tag);
		}
		cu.setTags(tags);
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("MalformedInput", e.getErrorCode());
			assertEquals("11 is not a valid index.", e.getMessage());
		}
	}

	/**
	 * 用户数量超过限制 500是上限，不报错
	 */
	@Test
	public void createUser_usersQuota500_ok_test() {
		String[] names = new String[500];
		String userName = "";
		for (int i = 1; i <= 499; i++) { // 499是因为，root1@test.com账户下已经存在一个子用户。
			userName = "testUser" + i;
			CreateUserRequest cu = new CreateUserRequest();
			cu.setUserName(userName);
			client.createUser(cu);
			names[i] = userName;
		}
		// 删除用户
		for (int i = 1; i <= 499; i++) {
			userName = names[i];
			DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
			deleteUserRequest.setUserName(userName);
			client.deleteUser(deleteUserRequest);
		}

	}

	/**
	 * 用户数量超过限制 500是上限，501报错
	 */
	@Test
	public void createUser_usersQuota501_fail_test() {
		String[] names = new String[500];
		String userName = "";
		for (int i = 1; i <= 499; i++) {
			userName = "testUser" + i;
			CreateUserRequest cu = new CreateUserRequest();
			cu.setUserName(userName);
			client.createUser(cu);
			names[i] = userName;
		}
		// 创建第501个用户
		userName = "testUser501";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("LimitExceeded", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Cannot exceed quota for UsersPerAccount: 500.", e.getMessage());
		}
		// 删除用户
		for (int i = 1; i <= 499; i++) {
			userName = names[i];
			DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
			deleteUserRequest.setUserName(userName);
			client.deleteUser(deleteUserRequest);
		}
	}

	/**
	 * 创建用户时，如果设置了重复的标签key，那么会报错。 key的大小写相同
	 */
	@Test
	public void createUser_sameTagKey_fail_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key1");
		tag1.setValue("2");
		tags.add(tag1);
		cu.setTags(tags);
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("InvalidInput", e.getErrorCode());
			assertEquals("Duplicate tag keys found. Please note that Tag keys are case insensitive.", e.getMessage());
		}
	}

	/**
	 * 创建用户时，如果设置了重复的标签key，那么会报错。 key的大小写不同
	 */
	@Test
	public void createUser_sameTagKey_fail_test2() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("KEY1");
		tag1.setValue("2");
		tags.add(tag1);
		cu.setTags(tags);
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("InvalidInput", e.getErrorCode());
			assertEquals("Duplicate tag keys found. Please note that Tag keys are case insensitive.", e.getMessage());
		}

	}

	@Test
	public void createUser_noTag_ok_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void createUser_noTag_ok_test2() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tags.add(tag);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void createUser_withTag_ok_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key2");
		tag1.setValue("2");
		tags.add(tag1);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * tagKey包含特殊字符_.:/=+-@文字
	 */
	@Test
	public void createUser_tagKey_specialCharacter_ok_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("Key1中文_.:/=+-@");
		tag.setValue("1");
		tags.add(tag);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * tagKey包含非法字符
	 */
	@Test
	public void createUser_tagKeyValue_specialCharacter_fail_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("#￥%……&");
		tag.setValue("@#$%^&*");
		tags.add(tag);
		cu.setTags(tags);
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"2 validation errors detected: Value '#￥%……&' at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+; Value '@#$%^&*' at 'tags.1.member.value' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*",
					e.getMessage());
		}

	}

	/**
	 * key长度限制：最小长度为1.最大长度为128。 测试长度为1
	 */
	@Test
	public void createUser_tagKey_length1_ok_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("1");
		tag.setValue("1");
		tags.add(tag);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * key长度限制：最小长度为1.最大长度为128。 测试长度为128
	 */
	@Test
	public void createUser_tagKey_length128_ok_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		String key = "";
		for (int i = 1; i <= 128; i++) {
			key += "a";
		}
		tag.setKey(key);
		tag.setValue("1");
		tags.add(tag);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * key长度限制：最小长度为1.最大长度为128。 测试长度为129
	 */
	@Test
	public void createUser_tagKey_length129_fail_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		String key = "";
		for (int i = 1; i <= 129; i++) {
			key += "a";
		}
		tag.setKey(key);
		tag.setValue("1");
		tags.add(tag);
		cu.setTags(tags);
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("1 validation error detected: Value '" + key
					+ "' at 'tags.1.member.key' failed to satisfy constraint: Member must have length less than or equal to 128",
					e.getMessage());
		}
	}

	@Test
	public void createUser_tagKey_length0_fail_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("");
		tag.setValue("aa");
		tags.add(tag);
		cu.setTags(tags);
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value '' at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+",
					e.getMessage());
		}
	}

	/**
	 * 添加标签时，没有设置标签的key
	 */
	@Test
	public void createUser_tagKeyNull_fail_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setValue("aa");
		tags.add(tag);
		cu.setTags(tags);
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'tags.1.member.key' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
	}

	/**
	 * 添加标签时，没有设置标签的value
	 */
	@Test
	public void createUser_tagValueNull_fail_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tags.add(tag);
		cu.setTags(tags);
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'tags.1.member.value' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
	}

	@Test
	public void createUser_tagValue_length0_ok_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("");
		tags.add(tag);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void createUser_tagValue_length256_ok_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		String value = "";
		for (int i = 1; i <= 256; i++) {
			value += "a";
		}
		tag.setValue(value);
		tags.add(tag);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void createUser_tagValue_length257_fail_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		String value = "";
		for (int i = 1; i <= 257; i++) {
			value += "a";
		}
		tag.setValue(value);
		tags.add(tag);
		cu.setTags(tags);
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("1 validation error detected: Value '" + value
					+ "' at 'tags.1.member.value' failed to satisfy constraint: Member must have length less than or equal to 256",
					e.getMessage());
		}
	}

	@Test
	public void createUser_tagValue_specialCharactor_ok_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("Key1中文_.:/=+-@");
		tags.add(tag);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);

	}

	/**
	 * 用户名包含中文
	 */
	@Test
	public void createUser_userName_containChinese_fail_test() {
		String userName = "a中文";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'userName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
					e.getMessage());
		}
	}

	/**
	 * 用户名包含空格
	 */
	@Test
	public void createUser_userName_containBlank_fail_test() {
		String userName = "a bc";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'userName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
					e.getMessage());
		}
	}

	/**
	 * 用户名包含以下字符：_ + =，.@ -
	 */
	@Test
	public void createUser_userName_withSpecialCharacters_ok_test() {
		String userName = "12Ab3_+=,.@-";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		System.out.println(result.toString());
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 用户名包含除_ + =，.@ -以外的特殊字符
	 */
	@Test
	public void createUser_userName_withSpecialCharacters_fail_test() {
		String userName = "12Ab3￥";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'userName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
					e.getMessage());
		}
	}

	/**
	 * 不设置userName
	 */
	@Test
	public void createUser_noUserName_fail_test() {
		CreateUserRequest cu = new CreateUserRequest();
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
	}

	@Test
	public void createGetDelUser_userName_length1_ok_test() {
		String userName = "1";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 检索用户
		GetUserRequest getUserRequest = new GetUserRequest();
		getUserRequest.setUserName(userName);
		GetUserResult get = client.getUser(getUserRequest);
		User getUser = get.getUser();
		assertEquals(userName, getUser.getUserName());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
		// 查询
		try {
			client.getUser(getUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("The user with name 1 cannot be found.", e.getMessage());
		}
	}

	@Test
	public void createGetDelUser_userName_length64_ok_test() {
		String userName = "";
		for (int i = 1; i <= 64; i++) {
			userName += "a";
		}
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 检索用户
		GetUserRequest getUserRequest = new GetUserRequest();
		getUserRequest.setUserName(userName);
		GetUserResult get = client.getUser(getUserRequest);
		User getUser = get.getUser();
		assertEquals(userName, getUser.getUserName());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
		// 查询
		try {
			client.getUser(getUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name " + userName + " cannot be found.", e.getMessage());
		}
	}

	@Test
	public void createUser_userName_lenggth65_fail_test() {
		String userName = "";
		for (int i = 1; i <= 65; i++) {
			userName += "a";
		}
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		try {
			client.createUser(cu);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals("1 validation error detected: Value '" + userName
					+ "' at 'userName' failed to satisfy constraint: Member must have length less than or equal to 64",
					e.getMessage());
		}
	}

	@Test
	public void getUser_noTag_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 检索用户信息
		GetUserRequest getUserRequest = new GetUserRequest();
		getUserRequest.setUserName("sdktestuser");
		GetUserResult get = client.getUser(getUserRequest);
		User getUser = get.getUser();
		assertEquals(userName, getUser.getUserName());
		assertTrue(getUser.getArn().length() > 0);
		assertTrue(getUser.getUserId().length() > 0);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void getUser_withTag_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key2");
		tag1.setValue("2");
		tags.add(tag1);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 检索用户信息
		GetUserRequest getUserRequest = new GetUserRequest();
		getUserRequest.setUserName("sdktestuser");
		GetUserResult get = client.getUser(getUserRequest);
		User getUser = get.getUser();
		System.out.println(getUser.toString());
		assertEquals(userName, getUser.getUserName());
		assertTrue(getUser.getArn().length() > 0);
		assertTrue(getUser.getUserId().length() > 0);
		assertTrue(getUser.getTags().size() == 2);
		List<Tag> gettags = getUser.getTags();
		assertEquals("key1", gettags.get(0).getKey());
		assertEquals("1", gettags.get(0).getValue());
		assertEquals("key2", gettags.get(1).getKey());
		assertEquals("2", gettags.get(1).getValue());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void getUser_withPassword_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, "12345678pw");
		client.createLoginProfile(createLoginProfileRequest);
		// 检索用户信息
		GetUserRequest getUserRequest = new GetUserRequest();
		getUserRequest.setUserName("sdktestuser");
		GetUserResult get = client.getUser(getUserRequest);
		User getUser = get.getUser();
		System.out.println(getUser.toString());
		assertEquals(userName, getUser.getUserName());
		assertTrue(getUser.getArn().length() > 0);
		assertTrue(getUser.getUserId().length() > 0);
		assertTrue(getUser.getTags().size() == 1);
		List<Tag> gettags = getUser.getTags();
		assertEquals("key1", gettags.get(0).getKey());
		assertEquals("1", gettags.get(0).getValue());
		// 删除用户
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(userName);
		client.deleteLoginProfile(deleteLoginProfileRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void getUser_userNameLength65_fail_test() {
		String userName = "";
		for (int i = 1; i <= 65; i++) {
			userName += "a";
		}
		GetUserRequest getUserRequest = new GetUserRequest();
		getUserRequest.setUserName(userName);
		try {
			client.getUser(getUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals("1 validation error detected: Value '" + userName
					+ "' at 'userName' failed to satisfy constraint: Member must have length less than or equal to 64",
					e.getMessage());
		}
	}

	@Test
	public void getUser_userNameLength0_fail_test() {
		String userName = "";
		GetUserRequest getUserRequest = new GetUserRequest();
		getUserRequest.setUserName(userName);
		try {
			client.getUser(getUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'userName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
					e.getMessage());
		}
	}

	@Test
	public void getUser_user_notExist_fail_test() {
		String userName = "noUserXX";
		GetUserRequest getUserRequest = new GetUserRequest();
		getUserRequest.setUserName(userName);
		try {
			client.getUser(getUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name " + userName + " cannot be found.", e.getMessage());
		}
	}

	/**
	 * 不输入userName参数，返回根用户
	 */
	@Test
	public void getUser_userNameNull_ok_test() {
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 查询
		GetUserRequest getUserRequest = new GetUserRequest();
		GetUserResult get = client.getUser(getUserRequest);
		User getUser = get.getUser();
		System.out.println(getUser.toString());
		assertEquals(subUser1, getUser.getUserName());
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName("sdktestuser");
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void deleteUser_ok_test() {
		// 创建
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
		// 查询
		GetUserRequest getUserRequest = new GetUserRequest();
		getUserRequest.setUserName(userName);
		try {
			client.getUser(getUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
		}
	}

	@Test
	public void deleteUser_user_notExist_fail_test() {
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName("xxxx");
		try {
			client.deleteUser(deleteUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name xxxx cannot be found.", e.getMessage());
		}
	}

	@Test
	public void deleteUser_userNameLength65_fail_test() {
		String userName = "";
		for (int i = 1; i <= 65; i++) {
			userName += "a";
		}
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		try {
			client.deleteUser(deleteUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals("1 validation error detected: Value '" + userName
					+ "' at 'userName' failed to satisfy constraint: Member must have length less than or equal to 64",
					e.getMessage());
		}
	}

	@Test
	public void deleteUser_userNameLength0_fail_test() {
		String userName = "";
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		try {
			client.deleteUser(deleteUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'userName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
					e.getMessage());
		}
	}

	@Test
	public void deleteUser_userNameNull_fail_test() {
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		try {
			client.deleteUser(deleteUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
	}

	/**
	 * 用户属于某个组时，不允许删除
	 */
	@Test
	public void deleteUser_hasGroup_fail_test() {
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		User user = result.getUser();
		assertEquals(userName, user.getUserName());
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		assertEquals(groupName, createResult.getGroup().getGroupName());
		//addUserToGroup
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, userName);
		client.addUserToGroup(addUserToGroupRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		try {
			client.deleteUser(deleteUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("DeleteConflict", e.getErrorCode());
			assertEquals(
					"Cannot delete entity, must remove users from group first.",
					e.getMessage());
		}
		//removeUserFromGroup
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		//deleteUser
		client.deleteUser(deleteUserRequest);
		//deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}
	
	/**
	 * 用户有登录密码时，不允许删除
	 */
	@Test
	public void deleteUser_hasPassword_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "a1234567";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		assertEquals(userName, profile.getUserName());
		//删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		try {
			client.deleteUser(deleteUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("DeleteConflict", e.getErrorCode());
			assertEquals(
					"Cannot delete entity, must delete login profile first.",
					e.getMessage());
		}
		// 刪除密码
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(userName);
		client.deleteLoginProfile(deleteLoginProfileRequest);
		// 删除用户
		client.deleteUser(deleteUserRequest);
	}
	
	@Test
	public void deleteUser_hasPolicy_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		client.createUser(cu);
		//创建策略，并绑定策略
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setUserName(userName);
		attachUserPolicyRequest.setPolicyArn(policyArn);
		client.attachUserPolicy(attachUserPolicyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		try {
			client.deleteUser(deleteUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("DeleteConflict", e.getErrorCode());
			assertEquals(
					"Cannot delete entity, must detach all policies first.",
					e.getMessage());
		}
		//解绑策略
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest(userName,policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		//删除用户
		client.deleteUser(deleteUserRequest);
		//删除策略
		DeletePolicyRequest request = new DeletePolicyRequest();
		request.setPolicyArn(policyArn);
		client.deletePolicy(request);
	}
	

	@Test
	public void listUsers_ok_test() {
		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		ListUsersResult list = client.listUsers(listUsersRequest);
		int userSize = list.getUsers().size();
		// 创建
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key2");
		tag1.setValue("2");
		tags.add(tag1);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 检索
		listUsersRequest = new ListUsersRequest();
		list = client.listUsers(listUsersRequest);
		assertFalse(list.getIsTruncated());
		assertEquals(userSize + 1, list.getUsers().size()); // 包括user1@oos.com、user2@oos.com、sdktestuser
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * list user时，marker参数非法，不是可打印的ASCII码
	 */
	@Test
	public void listUsers_marker0_fail_test() {
		// 创建
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setMarker("");
		try {
			client.listUsers(listUsersRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'marker' is invalid. It must contain only printable ASCII characters",
					e.getMessage());
		}
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void listUsers_maxItem0_fail_test() {
		// 创建
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setMaxItems(0);
		try {
			client.listUsers(listUsersRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",
					e.getMessage());
		}
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void listUsers_maxItem1_ok_test() {
		// 创建
		String userName = "a_1";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());

		String userName2 = "a_2";
		CreateUserRequest cu2 = new CreateUserRequest();
		cu2.setUserName(userName2);
		CreateUserResult result2 = client.createUser(cu2);
		assertEquals(userName2, result2.getUser().getUserName());
		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setMaxItems(1);
		ListUsersResult list = client.listUsers(listUsersRequest);
		assertTrue(list.getIsTruncated());
		List<UserResult> users = list.getUsers();
		assertEquals(1, users.size());
		for (UserResult user : users) {
			assertEquals(userName, user.getUserName());
		}
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);

		DeleteUserRequest deleteUserRequest2 = new DeleteUserRequest();
		deleteUserRequest2.setUserName(userName2);
		client.deleteUser(deleteUserRequest2);
	}

	@Test
	public void listUsers_maxItem2_ok_test() {
		// 创建
		String userName = "a_1";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());

		String userName2 = "a_2";
		CreateUserRequest cu2 = new CreateUserRequest();
		cu2.setUserName(userName2);
		CreateUserResult result2 = client.createUser(cu2);
		assertEquals(userName2, result2.getUser().getUserName());
		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setMaxItems(2);
		ListUsersResult list = client.listUsers(listUsersRequest);
		assertTrue(list.getIsTruncated());
		List<UserResult> users = list.getUsers();
		assertEquals(2, users.size());
		assertEquals(userName, list.getUsers().get(0).getUserName());
		assertEquals(userName2, list.getUsers().get(1).getUserName());
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);

		DeleteUserRequest deleteUserRequest2 = new DeleteUserRequest();
		deleteUserRequest2.setUserName(userName2);
		client.deleteUser(deleteUserRequest2);
	}

	@Test
	public void listUsers_maxItem1000_ok_test() {
		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		ListUsersResult list = client.listUsers(listUsersRequest);
		int userSize = list.getUsers().size();
		// 创建
		String userName = "a_1";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());

		String userName2 = "a_2";
		CreateUserRequest cu2 = new CreateUserRequest();
		cu2.setUserName(userName2);
		CreateUserResult result2 = client.createUser(cu2);
		assertEquals(userName2, result2.getUser().getUserName());
		// 检索
		listUsersRequest = new ListUsersRequest();
		listUsersRequest.setMaxItems(1000);
		list = client.listUsers(listUsersRequest);
		assertFalse(list.getIsTruncated());
		List<UserResult> users = list.getUsers();
		assertEquals(userSize + 2, users.size());
		assertEquals(userName, list.getUsers().get(0).getUserName());
		assertEquals(userName2, list.getUsers().get(1).getUserName());
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);

		DeleteUserRequest deleteUserRequest2 = new DeleteUserRequest();
		deleteUserRequest2.setUserName(userName2);
		client.deleteUser(deleteUserRequest2);
	}

	@Test
	public void listUsers_maxItem1001_fail_test() {
		// 创建
		String userName = "a_1";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());

		String userName2 = "a_2";
		CreateUserRequest cu2 = new CreateUserRequest();
		cu2.setUserName(userName2);
		CreateUserResult result2 = client.createUser(cu2);
		assertEquals(userName2, result2.getUser().getUserName());
		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setMaxItems(1001);
		try {
			client.listUsers(listUsersRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
					e.getMessage());
		}
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);

		DeleteUserRequest deleteUserRequest2 = new DeleteUserRequest();
		deleteUserRequest2.setUserName(userName2);
		client.deleteUser(deleteUserRequest2);
	}

	/**
	 * a_1,a_2,b_123 使用a_1匹配 userName匹配
	 */
	@Test
	public void listUsers_userNameMatch_ok_test1() {
		// 创建
		String userName = "a_1";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());

		String userName2 = "a_2";
		CreateUserRequest cu2 = new CreateUserRequest();
		cu2.setUserName(userName2);
		CreateUserResult result2 = client.createUser(cu2);
		assertEquals(userName2, result2.getUser().getUserName());

		String userName3 = "b_123";
		CreateUserRequest cu3 = new CreateUserRequest();
		cu3.setUserName(userName3);
		CreateUserResult result3 = client.createUser(cu3);
		assertEquals(userName3, result3.getUser().getUserName());

		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setUserName("a_1");
		ListUsersResult list = client.listUsers(listUsersRequest);
		assertFalse(list.getIsTruncated());
		assertEquals(1, list.getUsers().size());
		assertEquals(userName, list.getUsers().get(0).getUserName());

		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);

		DeleteUserRequest deleteUserRequest2 = new DeleteUserRequest();
		deleteUserRequest2.setUserName(userName2);
		client.deleteUser(deleteUserRequest2);
		DeleteUserRequest deleteUserRequest3 = new DeleteUserRequest();
		deleteUserRequest3.setUserName(userName3);
		client.deleteUser(deleteUserRequest3);
	}

	/**
	 * a_1,a_2,b_123 使用a匹配 userName模糊匹配
	 */
	@Test
	public void listUsers_userNameMatch_ok_test2() {
		// 创建
		String userName = "a_1";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());

		String userName2 = "a_2";
		CreateUserRequest cu2 = new CreateUserRequest();
		cu2.setUserName(userName2);
		CreateUserResult result2 = client.createUser(cu2);
		assertEquals(userName2, result2.getUser().getUserName());

		String userName3 = "b_123";
		CreateUserRequest cu3 = new CreateUserRequest();
		cu3.setUserName(userName3);
		CreateUserResult result3 = client.createUser(cu3);
		assertEquals(userName3, result3.getUser().getUserName());

		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setUserName("a");
		ListUsersResult list = client.listUsers(listUsersRequest);
		assertFalse(list.getIsTruncated());
		assertEquals(2, list.getUsers().size());
		assertEquals(userName, list.getUsers().get(0).getUserName());
		assertEquals(userName2, list.getUsers().get(1).getUserName());

		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);

		DeleteUserRequest deleteUserRequest2 = new DeleteUserRequest();
		deleteUserRequest2.setUserName(userName2);
		client.deleteUser(deleteUserRequest2);
		DeleteUserRequest deleteUserRequest3 = new DeleteUserRequest();
		deleteUserRequest3.setUserName(userName3);
		client.deleteUser(deleteUserRequest3);
	}

	/**
	 * a_1,a_2,b_123 使用_匹配
	 */
	@Test
	public void listUsers_userNameMatch_ok_test3() {
		// 创建
		String userName = "a_1";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());

		String userName2 = "a_2";
		CreateUserRequest cu2 = new CreateUserRequest();
		cu2.setUserName(userName2);
		CreateUserResult result2 = client.createUser(cu2);
		assertEquals(userName2, result2.getUser().getUserName());

		String userName3 = "b_123";
		CreateUserRequest cu3 = new CreateUserRequest();
		cu3.setUserName(userName3);
		CreateUserResult result3 = client.createUser(cu3);
		assertEquals(userName3, result3.getUser().getUserName());

		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setUserName("_");
		ListUsersResult list = client.listUsers(listUsersRequest);
		assertFalse(list.getIsTruncated());
		assertEquals(3, list.getUsers().size());
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);

		DeleteUserRequest deleteUserRequest2 = new DeleteUserRequest();
		deleteUserRequest2.setUserName(userName2);
		client.deleteUser(deleteUserRequest2);
		DeleteUserRequest deleteUserRequest3 = new DeleteUserRequest();
		deleteUserRequest3.setUserName(userName3);
		client.deleteUser(deleteUserRequest3);
	}

	/**
	 * a_1,a_2,b_123 使用123匹配
	 */
	@Test
	public void listUsers_userNameMatch_ok_test4() {
		// 创建
		String userName = "a_1";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());

		String userName2 = "a_2";
		CreateUserRequest cu2 = new CreateUserRequest();
		cu2.setUserName(userName2);
		CreateUserResult result2 = client.createUser(cu2);
		assertEquals(userName2, result2.getUser().getUserName());

		String userName3 = "b_123";
		CreateUserRequest cu3 = new CreateUserRequest();
		cu3.setUserName(userName3);
		CreateUserResult result3 = client.createUser(cu3);
		assertEquals(userName3, result3.getUser().getUserName());

		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setUserName("123");
		ListUsersResult list = client.listUsers(listUsersRequest);
		assertFalse(list.getIsTruncated());
		assertEquals(1, list.getUsers().size());
		assertEquals(userName3, list.getUsers().get(0).getUserName());
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);

		DeleteUserRequest deleteUserRequest2 = new DeleteUserRequest();
		deleteUserRequest2.setUserName(userName2);
		client.deleteUser(deleteUserRequest2);
		DeleteUserRequest deleteUserRequest3 = new DeleteUserRequest();
		deleteUserRequest3.setUserName(userName3);
		client.deleteUser(deleteUserRequest3);
	}

	@Test
	public void test() {
		long ownerId = -6273972570233703296L;
		String accountId = Long.toUnsignedString(ownerId, 36);
		System.out.println(accountId);
	}

	/**
	 * a_1,a_2,b_123 完全匹配 测试ak匹配
	 * 
	 * @throws IOException
	 */
	@Test
	public void listUsers_akMatch_ok_test() throws IOException {
		// 创建
		String userName = "a_1";
		cn.ctyun.oos.iam.server.entity.User user1 = new cn.ctyun.oos.iam.server.entity.User();
		user1.accountId = accountId;
		user1.userName = userName;
		user1.userId = "a_1_id";
		user1.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user1);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk1 = new AkSkMeta(owner.getId());
		aksk1.isRoot = 0;
		aksk1.userId = user1.userId;
		aksk1.userName = userName;
		aksk1.accessKey = "abc12345678901234";
		aksk1.setSecretKey("ssss");
		metaClient.akskInsert(aksk1);
		user1.accessKeys = new ArrayList<>();
		user1.userName = userName;
		user1.accessKeys.add(aksk1.accessKey);
		HBaseUtils.put(user1);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		String userName2 = "a_2";
		cn.ctyun.oos.iam.server.entity.User user2 = new cn.ctyun.oos.iam.server.entity.User();
		user2.accountId = accountId;
		user2.userName = userName2;
		user2.userId = "a_2_id";
		user2.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user2);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk21 = new AkSkMeta(owner.getId());
		aksk21.isRoot = 0;
		aksk21.userId = user2.userId;
		aksk21.userName = userName2;
		aksk21.accessKey = "abc123456789012345";
		aksk21.setSecretKey("ssss1");
		metaClient.akskInsert(aksk21);
		user2.accessKeys = new ArrayList<>();
		user2.userName = userName2;
		user2.accessKeys.add(aksk21.accessKey);
		HBaseUtils.put(user2);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		String userName3 = "b_123";
		cn.ctyun.oos.iam.server.entity.User user3 = new cn.ctyun.oos.iam.server.entity.User();
		user3.accountId = accountId;
		user3.userName = userName3;
		user3.userId = "b_123_id";
		user3.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user3);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk31 = new AkSkMeta(owner.getId());
		aksk31.isRoot = 0;
		aksk31.userId = user2.userId;
		aksk31.userName = userName3;
		aksk31.accessKey = "Abc1234567890123456";
		aksk31.setSecretKey("ssss3");
		metaClient.akskInsert(aksk31);
		user3.accessKeys = new ArrayList<>();
		user3.userName = userName3;
		user3.accessKeys.add(aksk31.accessKey);
		HBaseUtils.put(user3);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setAccessKeyId("Abc1234567890123456");
		ListUsersResult list = client.listUsers(listUsersRequest);
		assertFalse(list.getIsTruncated());
		assertEquals(1, list.getUsers().size());
		assertEquals(userName3, list.getUsers().get(0).getUserName());
		// 删除
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest();
		deleteAccessKeyRequest.setAccessKeyId("Abc1234567890123456");
		deleteAccessKeyRequest.setUserName(userName3);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId("abc123456789012345");
		deleteAccessKeyRequest.setUserName(userName2);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId("abc12345678901234");
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
		DeleteUserRequest deleteUserRequest2 = new DeleteUserRequest();
		deleteUserRequest2.setUserName(userName2);
		client.deleteUser(deleteUserRequest2);
		DeleteUserRequest deleteUserRequest3 = new DeleteUserRequest();
		deleteUserRequest3.setUserName(userName3);
		client.deleteUser(deleteUserRequest3);

	}

	/**
	 * a_1,a_2,b_123 模糊匹配
	 * 
	 * @throws IOException
	 */
	@Test
	public void listUsers_akMatch_ok_test2() throws IOException {
		// 创建
		String userName = "a_1";
		cn.ctyun.oos.iam.server.entity.User user1 = new cn.ctyun.oos.iam.server.entity.User();
		user1.accountId = accountId;
		user1.userName = userName;
		user1.userId = "a_1_id";
		user1.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user1);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk1 = new AkSkMeta(owner.getId());
		aksk1.isRoot = 0;
		aksk1.userId = user1.userId;
		aksk1.userName = userName;
		aksk1.accessKey = "abc12345678901234";
		aksk1.setSecretKey("ssss");
		metaClient.akskInsert(aksk1);
		user1.accessKeys = new ArrayList<>();
		user1.userName = userName;
		user1.accessKeys.add(aksk1.accessKey);
		HBaseUtils.put(user1);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		String userName2 = "a_2";
		cn.ctyun.oos.iam.server.entity.User user2 = new cn.ctyun.oos.iam.server.entity.User();
		user2.accountId = accountId;
		user2.userName = userName2;
		user2.userId = "a_2_id";
		user2.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user2);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk21 = new AkSkMeta(owner.getId());
		aksk21.isRoot = 0;
		aksk21.userId = user2.userId;
		aksk21.userName = userName2;
		aksk21.accessKey = "abc123456789012345";
		aksk21.setSecretKey("ssss1");
		metaClient.akskInsert(aksk21);
		user2.accessKeys = new ArrayList<>();
		user2.userName = userName2;
		user2.accessKeys.add(aksk21.accessKey);
		HBaseUtils.put(user2);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		String userName3 = "b_123";
		cn.ctyun.oos.iam.server.entity.User user3 = new cn.ctyun.oos.iam.server.entity.User();
		user3.accountId = accountId;
		user3.userName = userName3;
		user3.userId = "b_123_id";
		user3.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user3);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk31 = new AkSkMeta(owner.getId());
		aksk31.isRoot = 0;
		aksk31.userId = user2.userId;
		aksk31.userName = userName3;
		aksk31.accessKey = "Abc1234567890123456";
		aksk31.setSecretKey("ssss3");
		metaClient.akskInsert(aksk31);
		user3.accessKeys = new ArrayList<>();
		user3.userName = userName3;
		user3.accessKeys.add(aksk31.accessKey);
		HBaseUtils.put(user3);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setAccessKeyId("Abc12345678901234");
		ListUsersResult list = client.listUsers(listUsersRequest);
		assertFalse(list.getIsTruncated());
		assertEquals(3, list.getUsers().size());
		// 删除
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest();
		deleteAccessKeyRequest.setAccessKeyId("Abc1234567890123456");
		deleteAccessKeyRequest.setUserName(userName3);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId("abc123456789012345");
		deleteAccessKeyRequest.setUserName(userName2);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId("abc12345678901234");
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
		DeleteUserRequest deleteUserRequest2 = new DeleteUserRequest();
		deleteUserRequest2.setUserName(userName2);
		client.deleteUser(deleteUserRequest2);
		DeleteUserRequest deleteUserRequest3 = new DeleteUserRequest();
		deleteUserRequest3.setUserName(userName3);
		client.deleteUser(deleteUserRequest3);

	}

	/**
	 * a_1,a_2,b_123 模糊匹配
	 * 
	 * @throws IOException
	 */
	@Test
	public void listUsers_akMatch_ok_test3() throws IOException {
		// 创建
		String userName = "a_1";
		cn.ctyun.oos.iam.server.entity.User user1 = new cn.ctyun.oos.iam.server.entity.User();
		user1.accountId = accountId;
		user1.userName = userName;
		user1.userId = "a_1_id";
		user1.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user1);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk1 = new AkSkMeta(owner.getId());
		aksk1.isRoot = 0;
		aksk1.userId = user1.userId;
		aksk1.userName = userName;
		aksk1.accessKey = "abc12345678901234";
		aksk1.setSecretKey("ssss");
		metaClient.akskInsert(aksk1);
		user1.accessKeys = new ArrayList<>();
		user1.userName = userName;
		user1.accessKeys.add(aksk1.accessKey);
		HBaseUtils.put(user1);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		String userName2 = "a_2";
		cn.ctyun.oos.iam.server.entity.User user2 = new cn.ctyun.oos.iam.server.entity.User();
		user2.accountId = accountId;
		user2.userName = userName2;
		user2.userId = "a_2_id";
		user2.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user2);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk21 = new AkSkMeta(owner.getId());
		aksk21.isRoot = 0;
		aksk21.userId = user2.userId;
		aksk21.userName = userName2;
		aksk21.accessKey = "abc123456789012345";
		aksk21.setSecretKey("ssss1");
		metaClient.akskInsert(aksk21);
		user2.accessKeys = new ArrayList<>();
		user2.userName = userName2;
		user2.accessKeys.add(aksk21.accessKey);
		HBaseUtils.put(user2);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		String userName3 = "b_123";
		cn.ctyun.oos.iam.server.entity.User user3 = new cn.ctyun.oos.iam.server.entity.User();
		user3.accountId = accountId;
		user3.userName = userName3;
		user3.userId = "b_123_id";
		user3.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user3);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk31 = new AkSkMeta(owner.getId());
		aksk31.isRoot = 0;
		aksk31.userId = user2.userId;
		aksk31.userName = userName3;
		aksk31.accessKey = "Abc1234567890123456";
		aksk31.setSecretKey("ssss3");
		metaClient.akskInsert(aksk31);
		user3.accessKeys = new ArrayList<>();
		user3.userName = userName3;
		user3.accessKeys.add(aksk31.accessKey);
		HBaseUtils.put(user3);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setAccessKeyId("123456789");
		ListUsersResult list = client.listUsers(listUsersRequest);
		assertFalse(list.getIsTruncated());
		assertEquals(3, list.getUsers().size());
		// 删除
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest();
		deleteAccessKeyRequest.setAccessKeyId("Abc1234567890123456");
		deleteAccessKeyRequest.setUserName(userName3);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId("abc123456789012345");
		deleteAccessKeyRequest.setUserName(userName2);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId("abc12345678901234");
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
		DeleteUserRequest deleteUserRequest2 = new DeleteUserRequest();
		deleteUserRequest2.setUserName(userName2);
		client.deleteUser(deleteUserRequest2);
		DeleteUserRequest deleteUserRequest3 = new DeleteUserRequest();
		deleteUserRequest3.setUserName(userName3);
		client.deleteUser(deleteUserRequest3);
	}

	/**
	 * a_1,a_2,b_123 模糊匹配
	 * 
	 * @throws IOException
	 */
	@Test
	public void listUsers_akNotMatch_ok_test() throws IOException {
		// 创建
		String userName = "a_1";
		cn.ctyun.oos.iam.server.entity.User user1 = new cn.ctyun.oos.iam.server.entity.User();
		user1.accountId = accountId;
		user1.userName = userName;
		user1.userId = "a_1_id";
		user1.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user1);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk1 = new AkSkMeta(owner.getId());
		aksk1.isRoot = 0;
		aksk1.userId = user1.userId;
		aksk1.userName = userName;
		aksk1.accessKey = "abc12345678901234";
		aksk1.setSecretKey("ssss");
		metaClient.akskInsert(aksk1);
		user1.accessKeys = new ArrayList<>();
		user1.userName = userName;
		user1.accessKeys.add(aksk1.accessKey);
		HBaseUtils.put(user1);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		String userName2 = "a_2";
		cn.ctyun.oos.iam.server.entity.User user2 = new cn.ctyun.oos.iam.server.entity.User();
		user2.accountId = accountId;
		user2.userName = userName2;
		user2.userId = "a_2_id";
		user2.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user2);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk21 = new AkSkMeta(owner.getId());
		aksk21.isRoot = 0;
		aksk21.userId = user2.userId;
		aksk21.userName = userName2;
		aksk21.accessKey = "abc123456789012345";
		aksk21.setSecretKey("ssss1");
		metaClient.akskInsert(aksk21);
		user2.accessKeys = new ArrayList<>();
		user2.userName = userName2;
		user2.accessKeys.add(aksk21.accessKey);
		HBaseUtils.put(user2);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		String userName3 = "b_123";
		cn.ctyun.oos.iam.server.entity.User user3 = new cn.ctyun.oos.iam.server.entity.User();
		user3.accountId = accountId;
		user3.userName = userName3;
		user3.userId = "b_3_id";
		user3.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user3);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk31 = new AkSkMeta(owner.getId());
		aksk31.isRoot = 0;
		aksk31.userId = user2.userId;
		aksk31.userName = userName3;
		aksk31.accessKey = "Abc1234567890123456";
		aksk31.setSecretKey("ssss3");
		metaClient.akskInsert(aksk31);
		user3.accessKeys = new ArrayList<>();
		user3.userName = userName3;
		user3.accessKeys.add(aksk31.accessKey);
		HBaseUtils.put(user3);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setAccessKeyId("123456789AA");
		ListUsersResult list = client.listUsers(listUsersRequest);
		assertFalse(list.getIsTruncated());
		assertEquals(0, list.getUsers().size());
		// 删除
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest();
		deleteAccessKeyRequest.setAccessKeyId("Abc1234567890123456");
		deleteAccessKeyRequest.setUserName(userName3);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId("abc123456789012345");
		deleteAccessKeyRequest.setUserName(userName2);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId("abc12345678901234");
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
		DeleteUserRequest deleteUserRequest2 = new DeleteUserRequest();
		deleteUserRequest2.setUserName(userName2);
		client.deleteUser(deleteUserRequest2);
		DeleteUserRequest deleteUserRequest3 = new DeleteUserRequest();
		deleteUserRequest3.setUserName(userName3);
		client.deleteUser(deleteUserRequest3);
	}

	/**
	 * a_1,a_2,b_123 userName和AK联合，模糊匹配
	 * 
	 * @throws IOException
	 */
	@Test
	public void listUsers_userNameAndAk_match_ok_test() throws IOException {
		// 创建
		String userName = "a_1";
		cn.ctyun.oos.iam.server.entity.User user1 = new cn.ctyun.oos.iam.server.entity.User();
		user1.accountId = accountId;
		user1.userName = userName;
		user1.userId = "a_1_id";
		user1.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user1);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk1 = new AkSkMeta(owner.getId());
		aksk1.isRoot = 0;
		aksk1.userId = user1.userId;
		aksk1.userName = userName;
		aksk1.accessKey = "abc12345678901234";
		aksk1.setSecretKey("ssss");
		metaClient.akskInsert(aksk1);
		user1.accessKeys = new ArrayList<>();
		user1.userName = userName;
		user1.accessKeys.add(aksk1.accessKey);
		HBaseUtils.put(user1);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		String userName2 = "a_2";
		cn.ctyun.oos.iam.server.entity.User user2 = new cn.ctyun.oos.iam.server.entity.User();
		user2.accountId = accountId;
		user2.userName = userName2;
		user2.userId = "a_2_id";
		user2.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user2);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk21 = new AkSkMeta(owner.getId());
		aksk21.isRoot = 0;
		aksk21.userId = user2.userId;
		aksk21.userName = userName2;
		aksk21.accessKey = "abc123456789012345";
		aksk21.setSecretKey("ssss1");
		metaClient.akskInsert(aksk21);
		user2.accessKeys = new ArrayList<>();
		user2.userName = userName2;
		user2.accessKeys.add(aksk21.accessKey);
		HBaseUtils.put(user2);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		String userName3 = "b_123";
		cn.ctyun.oos.iam.server.entity.User user3 = new cn.ctyun.oos.iam.server.entity.User();
		user3.accountId = accountId;
		user3.userName = userName3;
		user3.userId = "b_123_id";
		user3.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user3);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk31 = new AkSkMeta(owner.getId());
		aksk31.isRoot = 0;
		aksk31.userId = user2.userId;
		aksk31.userName = userName3;
		aksk31.accessKey = "Abc1234567890123456";
		aksk31.setSecretKey("ssss3");
		metaClient.akskInsert(aksk31);
		user3.accessKeys = new ArrayList<>();
		user3.userName = userName3;
		user3.accessKeys.add(aksk31.accessKey);
		HBaseUtils.put(user3);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setUserName("a_");
		listUsersRequest.setAccessKeyId("Abc12345678901234");
		ListUsersResult list = client.listUsers(listUsersRequest);
		assertFalse(list.getIsTruncated());
		assertEquals(2, list.getUsers().size());
		// 删除
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest();
		deleteAccessKeyRequest.setAccessKeyId("Abc1234567890123456");
		deleteAccessKeyRequest.setUserName(userName3);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId("abc123456789012345");
		deleteAccessKeyRequest.setUserName(userName2);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId("abc12345678901234");
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
		DeleteUserRequest deleteUserRequest2 = new DeleteUserRequest();
		deleteUserRequest2.setUserName(userName2);
		client.deleteUser(deleteUserRequest2);
		DeleteUserRequest deleteUserRequest3 = new DeleteUserRequest();
		deleteUserRequest3.setUserName(userName3);
		client.deleteUser(deleteUserRequest3);

	}

	/**
	 * a_1,a_2,b_123 userName和AK联合，不匹配情况
	 * 
	 * @throws IOException
	 */
	@Test
	public void listUsers_userNameAndAk_notMatch_ok_test() throws IOException {
		// 创建
		String userName = "a_1";
		cn.ctyun.oos.iam.server.entity.User user1 = new cn.ctyun.oos.iam.server.entity.User();
		user1.accountId = accountId;
		user1.userName = userName;
		user1.userId = "a_1_id";
		user1.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user1);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk1 = new AkSkMeta(owner.getId());
		aksk1.isRoot = 0;
		aksk1.userId = user1.userId;
		aksk1.userName = userName;
		aksk1.accessKey = "abc12345678901234";
		aksk1.setSecretKey("ssss");
		metaClient.akskInsert(aksk1);
		user1.accessKeys = new ArrayList<>();
		user1.userName = userName;
		user1.accessKeys.add(aksk1.accessKey);
		HBaseUtils.put(user1);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		String userName2 = "a_2";
		cn.ctyun.oos.iam.server.entity.User user2 = new cn.ctyun.oos.iam.server.entity.User();
		user2.accountId = accountId;
		user2.userName = userName2;
		user2.userId = "a_2_id";
		user2.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user2);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk21 = new AkSkMeta(owner.getId());
		aksk21.isRoot = 0;
		aksk21.userId = user2.userId;
		aksk21.userName = userName2;
		aksk21.accessKey = "abc123456789012345";
		aksk21.setSecretKey("ssss1");
		metaClient.akskInsert(aksk21);
		user2.accessKeys = new ArrayList<>();
		user2.userName = userName2;
		user2.accessKeys.add(aksk21.accessKey);
		HBaseUtils.put(user2);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		String userName3 = "b_123";
		cn.ctyun.oos.iam.server.entity.User user3 = new cn.ctyun.oos.iam.server.entity.User();
		user3.accountId = accountId;
		user3.userName = userName3;
		user3.userId = "b_123_id";
		user3.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user3);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk31 = new AkSkMeta(owner.getId());
		aksk31.isRoot = 0;
		aksk31.userId = user2.userId;
		aksk31.userName = userName3;
		aksk31.accessKey = "Abc1234567890123456";
		aksk31.setSecretKey("ssss3");
		metaClient.akskInsert(aksk31);
		user3.accessKeys = new ArrayList<>();
		user3.userName = userName3;
		user3.accessKeys.add(aksk31.accessKey);
		HBaseUtils.put(user3);
		AccountSummaryService.increment(accountId, AccountSummary.USERS, 1);// 账户中的用户数量加1

		// 检索
		ListUsersRequest listUsersRequest = new ListUsersRequest();
		listUsersRequest.setUserName("a_");
		listUsersRequest.setAccessKeyId("Abc123456789012349");
		ListUsersResult list = client.listUsers(listUsersRequest);
		assertFalse(list.getIsTruncated());
		assertEquals(0, list.getUsers().size());
		// 删除
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest();
		deleteAccessKeyRequest.setAccessKeyId("Abc1234567890123456");
		deleteAccessKeyRequest.setUserName(userName3);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId("abc123456789012345");
		deleteAccessKeyRequest.setUserName(userName2);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId("abc12345678901234");
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
		DeleteUserRequest deleteUserRequest2 = new DeleteUserRequest();
		deleteUserRequest2.setUserName(userName2);
		client.deleteUser(deleteUserRequest2);
		DeleteUserRequest deleteUserRequest3 = new DeleteUserRequest();
		deleteUserRequest3.setUserName(userName3);
		client.deleteUser(deleteUserRequest3);

	}

	@Test
	public void listUserTags_ok_test() {
		// 创建
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key2");
		tag1.setValue("2");
		tags.add(tag1);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 检索tags
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult tagsResult = client.listUserTags(listUserTagsRequest);
		assertFalse(tagsResult.getIsTruncated());
		List<Tag> tagList = tagsResult.getTags();
		assertEquals(2, tagList.size());
		assertEquals("key1", tagList.get(0).getKey());
		assertEquals("1", tagList.get(0).getValue());
		assertEquals("key2", tagList.get(1).getKey());
		assertEquals("2", tagList.get(1).getValue());
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void listUserTags_marker0_fail_test() {
		// 创建
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key2");
		tag1.setValue("2");
		tags.add(tag1);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 检索tags
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		listUserTagsRequest.setMarker("");
		try {
			client.listUserTags(listUserTagsRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'marker' is invalid. It must contain only printable ASCII characters",
					e.getMessage());
		}
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void listUserTags_maxItems0_fail_test() {
		// 创建
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key2");
		tag1.setValue("2");
		tags.add(tag1);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 检索tags
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		listUserTagsRequest.setMaxItems(0);
		try {
			client.listUserTags(listUserTagsRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",
					e.getMessage());
		}
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void listUserTags_maxItems1_ok_test() {
		// 创建
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key2");
		tag1.setValue("2");
		tags.add(tag1);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 检索tags
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		listUserTagsRequest.setMaxItems(1);
		ListUserTagsResult tagsResult = client.listUserTags(listUserTagsRequest);
		assertTrue(tagsResult.getIsTruncated());
		List<Tag> tagList = tagsResult.getTags();
		assertEquals(1, tagList.size());
		assertEquals("key1", tagList.get(0).getKey());
		assertEquals("1", tagList.get(0).getValue());
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void listUserTags_maxItems2_ok_test() {
		// 创建
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key2");
		tag1.setValue("2");
		tags.add(tag1);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 检索tags
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		listUserTagsRequest.setMaxItems(2);
		ListUserTagsResult tagsResult = client.listUserTags(listUserTagsRequest);
		assertFalse(tagsResult.getIsTruncated());
		List<Tag> tagList = tagsResult.getTags();
		assertEquals(2, tagList.size());
		assertEquals("key1", tagList.get(0).getKey());
		assertEquals("1", tagList.get(0).getValue());
		assertEquals("key2", tagList.get(1).getKey());
		assertEquals("2", tagList.get(1).getValue());
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void listUserTags_maxItems3_ok_test() {
		// 创建
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key2");
		tag1.setValue("2");
		tags.add(tag1);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 检索tags
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		listUserTagsRequest.setMaxItems(3);
		ListUserTagsResult tagsResult = client.listUserTags(listUserTagsRequest);
		assertFalse(tagsResult.getIsTruncated());
		List<Tag> tagList = tagsResult.getTags();
		assertEquals(2, tagList.size());
		assertEquals("key1", tagList.get(0).getKey());
		assertEquals("1", tagList.get(0).getValue());
		assertEquals("key2", tagList.get(1).getKey());
		assertEquals("2", tagList.get(1).getValue());
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void listUserTags_maxItems1000_ok_test() {
		// 创建
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key2");
		tag1.setValue("2");
		tags.add(tag1);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 检索tags
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		listUserTagsRequest.setMaxItems(1000);
		ListUserTagsResult tagsResult = client.listUserTags(listUserTagsRequest);
		assertFalse(tagsResult.getIsTruncated());
		List<Tag> tagList = tagsResult.getTags();
		assertEquals(2, tagList.size());
		assertEquals("key1", tagList.get(0).getKey());
		assertEquals("1", tagList.get(0).getValue());
		assertEquals("key2", tagList.get(1).getKey());
		assertEquals("2", tagList.get(1).getValue());
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void listUserTags_maxItems1001_fail_test() {
		// 创建
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key2");
		tag1.setValue("2");
		tags.add(tag1);
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 检索tags
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		listUserTagsRequest.setMaxItems(1001);
		;
		try {
			client.listUserTags(listUserTagsRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
					e.getMessage());
		}
		// 删除
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void listUserTags_user_notExist_fail_test() {
		String userName = "noUserXXX";
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		try {
			client.listUserTags(listUserTagsRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name " + userName + " cannot be found.", e.getMessage());

		}
	}

	@Test
	public void listUserTags_userNameNull_fail_test() {
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		try {
			client.listUserTags(listUserTagsRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
	}

	@Test
	public void tagUser_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key2");
		tag1.setValue("2");
		tags.add(tag1);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 获取用户标签
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult list = client.listUserTags(listUserTagsRequest);
		assertEquals(2, list.getTags().size());
		assertEquals("key1", list.getTags().get(0).getKey());
		assertEquals("1", list.getTags().get(0).getValue());
		assertEquals("key2", list.getTags().get(1).getKey());
		assertEquals("2", list.getTags().get(1).getValue());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 添加标签时，标签数量超过限制
	 */
	@Test
	public void tagUser_LimitExceeded11_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		SdkInternalList<Tag> tags = new SdkInternalList<Tag>();
		for (int i = 1; i <= 10; i++) {
			Tag tag = new Tag();
			tag.setKey("key" + i);
			tag.setValue("aa");
			tags.add(tag);
		}
		cu.setTags(tags);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags2 = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("tag11");
		tag.setValue("1");
		tags2.add(tag);
		tagUserRequest.setTags(tags2);
		try {
			client.tagUser(tagUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("LimitExceeded", e.getErrorCode());
			assertEquals("The number of tags has reached the maximum limit.", e.getMessage());
		}
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void tagUser_user_notExist_fail_test() {
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName("noUserXXX");
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key2");
		tag1.setValue("2");
		tags.add(tag1);
		tagUserRequest.setTags(tags);
		try {
			client.tagUser(tagUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name noUserXXX cannot be found.", e.getMessage());
		}
	}

	@Test
	public void tagUser_userNameNull_fail_test() {
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(null);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("1");
		tags.add(tag);
		Tag tag1 = new Tag();
		tag1.setKey("key2");
		tag1.setValue("2");
		tags.add(tag1);
		tagUserRequest.setTags(tags);
		try {
			client.tagUser(tagUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
	}

	@Test
	public void tagUser_tagKeyNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey(null);
		tag.setValue("1");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		try {
			client.tagUser(tagUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'tags.1.member.key' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void tagUser_tagKey_length0_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("");
		tag.setValue("1");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		try {
			client.tagUser(tagUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '' at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+",
					e.getMessage());
		}
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void tagUser_tagKey128_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		String tagKeyName = "";
		for (int i = 1; i <= 128; i++) {
			tagKeyName += "k";
		}
		tag.setKey(tagKeyName);
		tag.setValue("1");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 获取用户标签
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult list = client.listUserTags(listUserTagsRequest);
		assertEquals(1, list.getTags().size());
		assertEquals(tagKeyName, list.getTags().get(0).getKey());
		assertEquals("1", list.getTags().get(0).getValue());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void tagUser_tagKey129_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		String tagKeyName = "";
		for (int i = 1; i <= 129; i++) {
			tagKeyName += "k";
		}
		tag.setKey(tagKeyName);
		tag.setValue("1");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		try {
			client.tagUser(tagUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals("1 validation error detected: Value '" + tagKeyName
					+ "' at 'tags.1.member.key' failed to satisfy constraint: Member must have length less than or equal to 128",
					e.getMessage());
		}
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void tagUser_tagKey_specialCharacter_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		String tagKeyName = "中  文12Ab_.:/=+-@";
		tag.setKey(tagKeyName);
		tag.setValue("1");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 获取用户标签
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult list = client.listUserTags(listUserTagsRequest);
		assertEquals(1, list.getTags().size());
		assertEquals(tagKeyName, list.getTags().get(0).getKey());
		assertEquals("1", list.getTags().get(0).getValue());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void tagUser_tagKeyValue_specialCharacter_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		String tagKeyName = "~！%￥……&*（）";
		tag.setKey(tagKeyName);
		tag.setValue("@#$%^");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		try {
			client.tagUser(tagUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"2 validation errors detected: Value '~！%￥……&*（）' at 'tags.1.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+; Value '@#$%^' at 'tags.1.member.value' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*",
					e.getMessage());
		}
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void tagUser_tagValueNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue(null);
		tags.add(tag);
		tagUserRequest.setTags(tags);
		try {
			client.tagUser(tagUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'tags.1.member.value' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void tagUser_tagValue_length0_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 获取用户标签
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult list = client.listUserTags(listUserTagsRequest);
		assertEquals(1, list.getTags().size());
		assertEquals("key1", list.getTags().get(0).getKey());
		assertEquals("", list.getTags().get(0).getValue());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void tagUser_tagValue_length256_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		String tagValue = "";
		for (int i = 1; i <= 256; i++) {
			tagValue += "v";
		}
		tag.setValue(tagValue);
		tags.add(tag);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 获取用户标签
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult list = client.listUserTags(listUserTagsRequest);
		assertEquals(1, list.getTags().size());
		assertEquals("key1", list.getTags().get(0).getKey());
		assertEquals(tagValue, list.getTags().get(0).getValue());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void tagUser_tagValue_length257_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		String tagValue = "";
		for (int i = 1; i <= 257; i++) {
			tagValue += "v";
		}
		tag.setValue(tagValue);
		tags.add(tag);
		tagUserRequest.setTags(tags);
		try {
			client.tagUser(tagUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals("1 validation error detected: Value '" + tagValue
					+ "' at 'tags.1.member.value' failed to satisfy constraint: Member must have length less than or equal to 256",
					e.getMessage());
		}
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void tagUser_tagValueSpecialCharacter_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		String tagValue = "中  文12Ab_.:/=+-@";
		tag.setKey("key1");
		tag.setValue(tagValue);
		tags.add(tag);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 获取用户标签
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult list = client.listUserTags(listUserTagsRequest);
		assertEquals(1, list.getTags().size());
		assertEquals("key1", list.getTags().get(0).getKey());
		assertEquals(tagValue, list.getTags().get(0).getValue());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 添加两个tagKeyName完全相同，但是tagValue不同的两个标签
	 */
	@Test
	public void tagUser_twoSameKey_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("a");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 添加第二个标签
		tags.get(0).setKey("key1");
		tags.get(0).setValue("b");
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 获取用户标签
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult list = client.listUserTags(listUserTagsRequest);
		assertEquals(1, list.getTags().size());
		assertEquals("key1", list.getTags().get(0).getKey());
		assertEquals("b", list.getTags().get(0).getValue());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 添加两个tagKeyName相同，但是大小写不同，tagValue不同的两个标签
	 */
	@Test
	public void tagUser_twoSameKeyIgnoreCase_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("a");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 添加第二个标签
		tags.get(0).setKey("Key1");
		tags.get(0).setValue("b");
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 获取用户标签
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult list = client.listUserTags(listUserTagsRequest);
		assertEquals(1, list.getTags().size());
		assertEquals("Key1", list.getTags().get(0).getKey());
		assertEquals("b", list.getTags().get(0).getValue());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void unTagUser_ok_test() {
		// 创建用户，创建标签
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("a");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 添加第二个标签
		tags.get(0).setKey("Key2");
		tags.get(0).setValue("b");
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// unTagUser
		UntagUserRequest untagUserRequest = new UntagUserRequest();
		untagUserRequest.setUserName(userName);
		List<String> tags2 = new ArrayList<String>();
		tags2.add("key1");
		untagUserRequest.setTagKeys(tags2);
		client.untagUser(untagUserRequest);
		// 查询用户Tag
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult tagsResult = client.listUserTags(listUserTagsRequest);
		assertEquals(1, tagsResult.getTags().size());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void unTagUser_ok_test2() {
		// 创建用户，创建标签
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("a");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 添加第二个标签
		tags.get(0).setKey("Key2");
		tags.get(0).setValue("b");
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// unTagUser
		UntagUserRequest untagUserRequest = new UntagUserRequest();
		untagUserRequest.setUserName(userName);
		List<String> tags2 = new ArrayList<String>();
		tags2.add("key1");
		tags2.add("Key2");
		untagUserRequest.setTagKeys(tags2);
		client.untagUser(untagUserRequest);
		// 查询用户Tag
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult tagsResult = client.listUserTags(listUserTagsRequest);
		assertEquals(0, tagsResult.getTags().size());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 指定的tagKey大小写不同，同样可以删除成功
	 */
	@Test
	public void unTagUser_ok_test3() {
		// 创建用户，创建标签
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("a");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 添加第二个标签
		tags.get(0).setKey("Key2");
		tags.get(0).setValue("b");
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// unTagUser
		UntagUserRequest untagUserRequest = new UntagUserRequest();
		untagUserRequest.setUserName(userName);
		List<String> tags2 = new ArrayList<String>();
		tags2.add("Key1");
		untagUserRequest.setTagKeys(tags2);
		client.untagUser(untagUserRequest);
		// 查询用户Tag
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult tagsResult = client.listUserTags(listUserTagsRequest);
		assertEquals(1, tagsResult.getTags().size());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 删除不存在的标签
	 */
	@Test
	public void unTagUser_noTag_ok_test() {
		// 创建用户，创建标签
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("a");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 添加第二个标签
		tags.get(0).setKey("Key2");
		tags.get(0).setValue("b");
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// unTagUser
		UntagUserRequest untagUserRequest = new UntagUserRequest();
		untagUserRequest.setUserName(userName);
		List<String> tags2 = new ArrayList<String>();
		tags2.add("XXx");
		untagUserRequest.setTagKeys(tags2);
		client.untagUser(untagUserRequest);
		// 查询用户Tag
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult tagsResult = client.listUserTags(listUserTagsRequest);
		assertEquals(2, tagsResult.getTags().size());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 不指定标签情况，成功。
	 */
	@Test
	public void unTagUser_noTagParam_ok_test() {
		// 创建用户，创建标签
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("a");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 添加第二个标签
		tags.get(0).setKey("Key2");
		tags.get(0).setValue("b");
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// unTagUser
		UntagUserRequest untagUserRequest = new UntagUserRequest();
		untagUserRequest.setUserName(userName);
		client.untagUser(untagUserRequest);
		// 查询用户Tag
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult tagsResult = client.listUserTags(listUserTagsRequest);
		assertEquals(2, tagsResult.getTags().size());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 指定用户不存在的情况
	 */
	@Test
	public void unTagUser_noUser_notExist_fail_test() {
		// 创建用户，创建标签
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("a");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 添加第二个标签
		tags.get(0).setKey("Key2");
		tags.get(0).setValue("b");
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// unTagUser
		UntagUserRequest untagUserRequest = new UntagUserRequest();
		untagUserRequest.setUserName("noUserxxx");
		List<String> tags2 = new ArrayList<String>();
		tags2.add("key1");
		untagUserRequest.setTagKeys(tags2);
		try {
			client.untagUser(untagUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name noUserxxx cannot be found.", e.getMessage());

		}
		// 查询用户Tag
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult tagsResult = client.listUserTags(listUserTagsRequest);
		assertEquals(2, tagsResult.getTags().size());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 不指定用户的情况
	 */
	@Test
	public void unTagUser_userNameNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 添加标签
		TagUserRequest tagUserRequest = new TagUserRequest();
		tagUserRequest.setUserName(userName);
		List<Tag> tags = new ArrayList<Tag>();
		Tag tag = new Tag();
		tag.setKey("key1");
		tag.setValue("a");
		tags.add(tag);
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// 添加第二个标签
		tags.get(0).setKey("Key2");
		tags.get(0).setValue("b");
		tagUserRequest.setTags(tags);
		client.tagUser(tagUserRequest);
		// unTagUser
		UntagUserRequest untagUserRequest = new UntagUserRequest();
		List<String> tags2 = new ArrayList<String>();
		tags2.add("key1");
		untagUserRequest.setTagKeys(tags2);
		try {
			client.untagUser(untagUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 查询用户Tag
		ListUserTagsRequest listUserTagsRequest = new ListUserTagsRequest();
		listUserTagsRequest.setUserName(userName);
		ListUserTagsResult tagsResult = client.listUserTags(listUserTagsRequest);
		assertEquals(2, tagsResult.getTags().size());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
		deleteUserRequest.setUserName(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 一个用户绑定了1个组
	 */
	@Test
	public void listGroupsForUser_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建组，并添加用户到组
		String groupName = "grouptest1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest(groupName);
		client.createGroup(createGroupRequest);
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, userName);
		client.addUserToGroup(addUserToGroupRequest);
		// 列出用户所属IAM组
		ListGroupsForUserRequest listGroupsForUserRequest = new ListGroupsForUserRequest(userName);
		ListGroupsForUserResult groupsResult = client.listGroupsForUser(listGroupsForUserRequest);
		List<com.amazonaws.services.identitymanagement.model.Group> groups = groupsResult.getGroups();
		assertEquals(1, groups.size());
		assertEquals(groupName, groups.get(0).getGroupName());
		// 解除用户所属组，删除用户、组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);

	}

	/**
	 * 一个用户绑定了2个组
	 */
	@Test
	public void listGroupsForUser_ok_test2() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建组，并添加用户到组
		String groupName = "grouptest1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest(groupName);
		client.createGroup(createGroupRequest);
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, userName);
		client.addUserToGroup(addUserToGroupRequest);

		String groupName2 = "grouptest2";
		createGroupRequest = new CreateGroupRequest(groupName2);
		client.createGroup(createGroupRequest);
		addUserToGroupRequest = new AddUserToGroupRequest(groupName2, userName);
		client.addUserToGroup(addUserToGroupRequest);
		// 列出用户所属IAM组
		ListGroupsForUserRequest listGroupsForUserRequest = new ListGroupsForUserRequest(userName);
		ListGroupsForUserResult groupsResult = client.listGroupsForUser(listGroupsForUserRequest);
		List<com.amazonaws.services.identitymanagement.model.Group> groups = groupsResult.getGroups();
		assertEquals(2, groups.size());
		assertEquals(groupName, groups.get(0).getGroupName());
		assertEquals(groupName2, groups.get(1).getGroupName());
		for (com.amazonaws.services.identitymanagement.model.Group group : groups) {
			System.out.println(group.getGroupName());
			System.out.println(group.getGroupId());
			System.out.println(group.getArn());
			System.out.println(group.getCreateDate());
		}
		// 解除用户所属组，删除用户、组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName2, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest = new DeleteGroupRequest(groupName2);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 一个用户绑定了0个组
	 */
	@Test
	public void listGroupsForUser_ok_test3() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 列出用户所属IAM组
		ListGroupsForUserRequest listGroupsForUserRequest = new ListGroupsForUserRequest(userName);
		ListGroupsForUserResult groupsResult = client.listGroupsForUser(listGroupsForUserRequest);
		List<com.amazonaws.services.identitymanagement.model.Group> groups = groupsResult.getGroups();
		assertEquals(0, groups.size());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 指定的用户不存在
	 */
	@Test
	public void listGroupsForUser_user_notExist_fail_test() {
		String userName = "noUserXXX";
		ListGroupsForUserRequest listGroupsForUserRequest = new ListGroupsForUserRequest(userName);
		try {
			client.listGroupsForUser(listGroupsForUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name noUserXXX cannot be found.", e.getMessage());

		}
	}

	/**
	 * 不指定用户参数
	 */
	@Test
	public void listGroupsForUser_userParamNull_fail_test() {
		ListGroupsForUserRequest listGroupsForUserRequest = new ListGroupsForUserRequest();
		try {
			client.listGroupsForUser(listGroupsForUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
	}

	/**
	 * 一个用户绑定了2个组,MaxItems定义为1
	 */
	@Test
	public void listGroupsForUser_maxItems1_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建组，并添加用户到组
		String groupName = "grouptest1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest(groupName);
		client.createGroup(createGroupRequest);
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, userName);
		client.addUserToGroup(addUserToGroupRequest);

		String groupName2 = "grouptest2";
		createGroupRequest = new CreateGroupRequest(groupName2);
		client.createGroup(createGroupRequest);
		addUserToGroupRequest = new AddUserToGroupRequest(groupName2, userName);
		client.addUserToGroup(addUserToGroupRequest);
		// 列出用户所属IAM组
		ListGroupsForUserRequest listGroupsForUserRequest = new ListGroupsForUserRequest(userName);
		listGroupsForUserRequest.setMaxItems(1);
		ListGroupsForUserResult groupsResult = client.listGroupsForUser(listGroupsForUserRequest);
		assertTrue(groupsResult.getIsTruncated());
		List<com.amazonaws.services.identitymanagement.model.Group> groups = groupsResult.getGroups();
		assertEquals(1, groups.size());
		assertEquals(groupName, groups.get(0).getGroupName());
		// 解除用户所属组，删除用户、组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName2, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest = new DeleteGroupRequest(groupName2);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 一个用户绑定了2个组,MaxItems定义为0
	 */
	@Test
	public void listGroupsForUser_maxItems0_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建组，并添加用户到组
		String groupName = "grouptest1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest(groupName);
		client.createGroup(createGroupRequest);
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, userName);
		client.addUserToGroup(addUserToGroupRequest);

		String groupName2 = "grouptest2";
		createGroupRequest = new CreateGroupRequest(groupName2);
		client.createGroup(createGroupRequest);
		addUserToGroupRequest = new AddUserToGroupRequest(groupName2, userName);
		client.addUserToGroup(addUserToGroupRequest);
		// 列出用户所属IAM组
		ListGroupsForUserRequest listGroupsForUserRequest = new ListGroupsForUserRequest(userName);
		listGroupsForUserRequest.setMaxItems(0);
		try {
			client.listGroupsForUser(listGroupsForUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",
					e.getMessage());
		}
		// 解除用户所属组，删除用户、组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName2, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest = new DeleteGroupRequest(groupName2);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 一个用户绑定了2个组,MaxItems定义为1000
	 */
	@Test
	public void listGroupsForUser_maxItems1000_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建组，并添加用户到组
		String groupName = "grouptest1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest(groupName);
		client.createGroup(createGroupRequest);
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, userName);
		client.addUserToGroup(addUserToGroupRequest);

		String groupName2 = "grouptest2";
		createGroupRequest = new CreateGroupRequest(groupName2);
		client.createGroup(createGroupRequest);
		addUserToGroupRequest = new AddUserToGroupRequest(groupName2, userName);
		client.addUserToGroup(addUserToGroupRequest);
		// 列出用户所属IAM组
		ListGroupsForUserRequest listGroupsForUserRequest = new ListGroupsForUserRequest(userName);
		listGroupsForUserRequest.setMaxItems(1000);
		ListGroupsForUserResult groupsResult = client.listGroupsForUser(listGroupsForUserRequest);
		assertFalse(groupsResult.getIsTruncated());
		List<com.amazonaws.services.identitymanagement.model.Group> groups = groupsResult.getGroups();
		assertEquals(2, groups.size());
		assertEquals(groupName, groups.get(0).getGroupName());
		assertEquals(groupName2, groups.get(1).getGroupName());
		// 解除用户所属组，删除用户、组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName2, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest = new DeleteGroupRequest(groupName2);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 一个用户绑定了2个组,MaxItems定义为1001
	 */
	@Test
	public void listGroupsForUser_maxItems1001_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建组，并添加用户到组
		String groupName = "grouptest1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest(groupName);
		client.createGroup(createGroupRequest);
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, userName);
		client.addUserToGroup(addUserToGroupRequest);

		String groupName2 = "grouptest2";
		createGroupRequest = new CreateGroupRequest(groupName2);
		client.createGroup(createGroupRequest);
		addUserToGroupRequest = new AddUserToGroupRequest(groupName2, userName);
		client.addUserToGroup(addUserToGroupRequest);
		// 列出用户所属IAM组
		ListGroupsForUserRequest listGroupsForUserRequest = new ListGroupsForUserRequest(userName);
		listGroupsForUserRequest.setMaxItems(1001);
		try {
			client.listGroupsForUser(listGroupsForUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
					e.getMessage());
		}
		// 解除用户所属组，删除用户、组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName2, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest = new DeleteGroupRequest(groupName2);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 一个用户绑定了2个组,Marker设置为""
	 */
	@Test
	public void listGroupsForUser_marker0_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建组，并添加用户到组
		String groupName = "grouptest1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest(groupName);
		client.createGroup(createGroupRequest);
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, userName);
		client.addUserToGroup(addUserToGroupRequest);

		String groupName2 = "grouptest2";
		createGroupRequest = new CreateGroupRequest(groupName2);
		client.createGroup(createGroupRequest);
		addUserToGroupRequest = new AddUserToGroupRequest(groupName2, userName);
		client.addUserToGroup(addUserToGroupRequest);
		// 列出用户所属IAM组
		ListGroupsForUserRequest listGroupsForUserRequest = new ListGroupsForUserRequest(userName);
		listGroupsForUserRequest.setMarker("");
		try {
			client.listGroupsForUser(listGroupsForUserRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
		}
		// 解除用户所属组，删除用户、组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName2, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest = new DeleteGroupRequest(groupName2);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 用户名包含特殊字符
	 */
	@Test
	public void listGroupsForUser_userNameSpecialCharacter_ok_test() {
		// 创建用户
		String userName = "12Ab3_+=,.@-";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建组，并添加用户到组
		String groupName = "grouptest1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest(groupName);
		client.createGroup(createGroupRequest);
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, userName);
		client.addUserToGroup(addUserToGroupRequest);

		String groupName2 = "grouptest2";
		createGroupRequest = new CreateGroupRequest(groupName2);
		client.createGroup(createGroupRequest);
		addUserToGroupRequest = new AddUserToGroupRequest(groupName2, userName);
		client.addUserToGroup(addUserToGroupRequest);
		// 列出用户所属IAM组
		ListGroupsForUserRequest listGroupsForUserRequest = new ListGroupsForUserRequest(userName);
		listGroupsForUserRequest.setMaxItems(1000);
		ListGroupsForUserResult groupsResult = client.listGroupsForUser(listGroupsForUserRequest);
		assertFalse(groupsResult.getIsTruncated());
		List<com.amazonaws.services.identitymanagement.model.Group> groups = groupsResult.getGroups();
		assertEquals(2, groups.size());
		assertEquals(groupName, groups.get(0).getGroupName());
		assertEquals(groupName2, groups.get(1).getGroupName());
		// 解除用户所属组，删除用户、组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName2, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest = new DeleteGroupRequest(groupName2);
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void createAK_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(ak.getAccessKeyId());
		System.out.println(ak.getSecretAccessKey());
		System.out.println(ak.getUserName());
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 删除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 创建密钥时，不指定userName，根据发送签名请求的AccessKeyID来设置用户名 使用子用户密钥
	 */
	@Test
	public void createAK_nouserNameParam_ok_test() {
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(ak.getAccessKeyId());
		System.out.println(ak.getSecretAccessKey());
		System.out.println(ak.getUserName());
		String userName = ak.getUserName();
		assertEquals("Active", ak.getStatus());
		assertEquals(subUser1, ak.getUserName());
		// 删除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
	}

	/**
	 * 创建密钥，不指定用户名，根据发送签名请求的AccessKeyID来设置用户名 默认使用根用户
	 */
	@Test
	public void createAK_nouserNameParam_root_ok_test() {
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		CreateAccessKeyResult akResult = rootClient.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(ak.getAccessKeyId());
		System.out.println(ak.getSecretAccessKey());
		System.out.println(ak.getUserName());
		String userName = ak.getUserName();
		assertEquals("Active", ak.getStatus());
		assertEquals(ownerName, ak.getUserName());
		// 删除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		rootClient.deleteAccessKey(deleteAccessKeyRequest);
	}

	/**
	 * 创建密钥时，指定的username不存在
	 */
	@Test
	public void createAK_user_notExist_fail_test() {
		// 创建密钥
		String userName = "noUserXX";
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		try {
			client.createAccessKey(createAccessKeyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name noUserXX cannot be found.", e.getMessage());
		}
	}

	@Test
	public void createAK_userName_withSpecialCharacter_ok_test() {
		// 创建用户
		String userName = "12Ab3_+=,.@-";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(ak.getAccessKeyId());
		System.out.println(ak.getSecretAccessKey());
		System.out.println(ak.getUserName());
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 删除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 为子用户创建3个密钥 前两个密钥创建成功，第三个密钥创建失败
	 */
	@Test
	public void createAK_limitExceeded3_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建第一个密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 创建第二个密钥
		akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak2 = akResult.getAccessKey();
		String akId2 = ak2.getAccessKeyId();
		assertEquals(userName, ak2.getUserName());
		assertEquals("Active", ak2.getStatus());
		// 创建第三个密钥失败
		try {
			client.createAccessKey(createAccessKeyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("LimitExceeded", e.getErrorCode());
			assertEquals("Cannot exceed quota for AccessKeysPerUser: 2.", e.getMessage());
		}
		// 删除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId2);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 创建、删除、查询子用户密钥，指定UserName
	 */
	@Test
	public void createDeleteListAk_subUser_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 刪除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		listAccessKeysRequest.setUserName(userName);
		ListAccessKeysResult listResult = client.listAccessKeys(listAccessKeysRequest);
		assertEquals(0, listResult.getAccessKeyMetadata().size());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 创建、删除、查询子用户密钥，不指定UserName
	 */
	@Test
	public void createDeleteListAk_subUser_ok_test2() {
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(subUser1, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		ListAccessKeysResult listResult = client.listAccessKeys(listAccessKeysRequest);
		int size = listResult.getAccessKeyMetadata().size();
		// 刪除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 查询密钥
		listAccessKeysRequest = new ListAccessKeysRequest();
		listResult = client.listAccessKeys(listAccessKeysRequest);
		assertEquals(size - 1, listResult.getAccessKeyMetadata().size());
	}

	/**
	 * 创建、删除、查询根用户的密钥,不指定userName
	 */
	@Test
	public void createDeleteListAk_rootUser_ok_test() {
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		CreateAccessKeyResult akResult = rootClient.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		assertEquals(ownerName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		ListAccessKeysResult listResult = rootClient.listAccessKeys(listAccessKeysRequest);
		int size = listResult.getAccessKeyMetadata().size();
		// 刪除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		rootClient.deleteAccessKey(deleteAccessKeyRequest);
		// 查询密钥
		listAccessKeysRequest = new ListAccessKeysRequest();
		listResult = rootClient.listAccessKeys(listAccessKeysRequest);
		assertEquals(size - 1, listResult.getAccessKeyMetadata().size());
	}

	@Test
	public void deleteAk_akNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 刪除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest();
		deleteAccessKeyRequest.setUserName(userName);
		try {
			client.deleteAccessKey(deleteAccessKeyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'accessKeyId' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 删除密钥
		deleteAccessKeyRequest.setAccessKeyId(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 删除ak时，指定的AK不存在
	 */
	@Test
	public void deleteAk_ak_notExist_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 刪除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest("26ece9ef2066415153a6");
		deleteAccessKeyRequest.setUserName(userName);
		try {
			client.deleteAccessKey(deleteAccessKeyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The Access Key with id 26ece9ef2066415153a6 cannot be found.", e.getMessage());
		}
		// 删除密钥
		deleteAccessKeyRequest.setAccessKeyId(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 删除ak时，指定的AK不符合ak规则，长度不够
	 */
	@Test
	public void deleteAk_ak_invalid_fail_test2() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 刪除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest("11122");
		deleteAccessKeyRequest.setUserName(userName);
		try {
			client.deleteAccessKey(deleteAccessKeyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '11122' at 'accessKeyId' failed to satisfy constraint: Member must have length greater than or equal to 16",
					e.getMessage());
		}
		// 删除密钥
		deleteAccessKeyRequest.setAccessKeyId(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 查询子用户密钥，只有一个密钥 指定userName
	 */
	@Test
	public void listAk_numb1_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		listAccessKeysRequest.setUserName(userName);
		ListAccessKeysResult listResult = client.listAccessKeys(listAccessKeysRequest);
		assertFalse(listResult.getIsTruncated());
		System.out.println(listResult.getUserName());
		assertEquals(userName, listResult.getUserName());
		assertEquals(1, listResult.getAccessKeyMetadata().size());
		AccessKeyMetadata akMeta = listResult.getAccessKeyMetadata().get(0);
		assertEquals(akId, akMeta.getAccessKeyId());
		assertEquals(userName, akMeta.getUserName());
		assertEquals("Active", akMeta.getStatus());
		// 刪除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 查询子用户密钥，有2个密钥 指定userName
	 */
	@Test
	public void listAk_numb2_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());

		akResult = client.createAccessKey(createAccessKeyRequest);
		String akId2 = akResult.getAccessKey().getAccessKeyId();
		System.out.println(akId2);
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		listAccessKeysRequest.setUserName(userName);
		ListAccessKeysResult listResult = client.listAccessKeys(listAccessKeysRequest);
		assertFalse(listResult.getIsTruncated());
		assertEquals(userName, listResult.getUserName());
		assertEquals(2, listResult.getAccessKeyMetadata().size());
		for (AccessKeyMetadata akMeta : listResult.getAccessKeyMetadata()) {
			System.out.println(akMeta.getAccessKeyId());
		}
		// 刪除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId(akId2);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 查询子用户密钥，有0个密钥 指定userName
	 */
	@Test
	public void listAk_numb0_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		listAccessKeysRequest.setUserName(userName);
		ListAccessKeysResult listResult = client.listAccessKeys(listAccessKeysRequest);
		assertFalse(listResult.getIsTruncated());
		assertEquals(0, listResult.getAccessKeyMetadata().size());
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 查询子用户密钥，有2个密钥 不指定userName
	 */
	@Test
	public void listAk_numb2_ok_test2() {
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(subUser1, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		ListAccessKeysResult listResult = client.listAccessKeys(listAccessKeysRequest);
		assertFalse(listResult.getIsTruncated());
		assertEquals(subUser1, listResult.getUserName());
		assertEquals(2, listResult.getAccessKeyMetadata().size());
		for (AccessKeyMetadata akMeta : listResult.getAccessKeyMetadata()) {
			System.out.println(akMeta.getAccessKeyId());
		}
		// 刪除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		client.deleteAccessKey(deleteAccessKeyRequest);
	}

	@Test
	public void listAk_maxItems1_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());

		akResult = client.createAccessKey(createAccessKeyRequest);
		String akId2 = akResult.getAccessKey().getAccessKeyId();
		System.out.println(akId2);
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		listAccessKeysRequest.setUserName(userName);
		listAccessKeysRequest.setMaxItems(1);
		ListAccessKeysResult listResult = client.listAccessKeys(listAccessKeysRequest);
		assertTrue(listResult.getIsTruncated());
		assertEquals(userName, listResult.getUserName());
		assertEquals(1, listResult.getAccessKeyMetadata().size());
		// 刪除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId(akId2);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void listAk_maxItems0_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());

		akResult = client.createAccessKey(createAccessKeyRequest);
		String akId2 = akResult.getAccessKey().getAccessKeyId();
		System.out.println(akId2);
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		listAccessKeysRequest.setUserName(userName);
		listAccessKeysRequest.setMaxItems(0);
		try {
			client.listAccessKeys(listAccessKeysRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",
					e.getMessage());
		}
		// 刪除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId(akId2);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void listAk_maxItems1001_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());

		akResult = client.createAccessKey(createAccessKeyRequest);
		String akId2 = akResult.getAccessKey().getAccessKeyId();
		System.out.println(akId2);
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		listAccessKeysRequest.setUserName(userName);
		listAccessKeysRequest.setMaxItems(1001);
		try {
			client.listAccessKeys(listAccessKeysRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
					e.getMessage());
		}
		// 刪除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId(akId2);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void listAk_marker_length0_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());

		akResult = client.createAccessKey(createAccessKeyRequest);
		String akId2 = akResult.getAccessKey().getAccessKeyId();
		System.out.println(akId2);
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		listAccessKeysRequest.setUserName(userName);
		listAccessKeysRequest.setMarker("");
		try {
			client.listAccessKeys(listAccessKeysRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'marker' is invalid. It must contain only printable ASCII characters",
					e.getMessage());
		}
		// 刪除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		deleteAccessKeyRequest.setAccessKeyId(akId2);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 指定UserName
	 */
	@Test
	public void updateAK_subUser_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 修改密钥
		UpdateAccessKeyRequest updateAccessKeyRequest = new UpdateAccessKeyRequest(akId, "Inactive");
		updateAccessKeyRequest.setUserName(userName);
		client.updateAccessKey(updateAccessKeyRequest);
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		listAccessKeysRequest.setUserName(userName);
		ListAccessKeysResult listResult = client.listAccessKeys(listAccessKeysRequest);
		assertFalse(listResult.getIsTruncated());
		assertEquals(1, listResult.getAccessKeyMetadata().size());
		assertEquals("Inactive", listResult.getAccessKeyMetadata().get(0).getStatus());
		// 修改密钥
		updateAccessKeyRequest.setStatus("Active");
		client.updateAccessKey(updateAccessKeyRequest);
		// 查询密钥
		listResult = client.listAccessKeys(listAccessKeysRequest);
		assertEquals("Active", listResult.getAccessKeyMetadata().get(0).getStatus());
		// 删除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 子用户，不指定UserName
	 */
	@Test
	public void updateAK_subUser_ok_test2() {
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(subUser1, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 修改密钥
		UpdateAccessKeyRequest updateAccessKeyRequest = new UpdateAccessKeyRequest(akId, "Inactive");
		client.updateAccessKey(updateAccessKeyRequest);
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		ListAccessKeysResult listResult = client.listAccessKeys(listAccessKeysRequest);
		assertFalse(listResult.getIsTruncated());
		for (AccessKeyMetadata akMeta : listResult.getAccessKeyMetadata()) {
			if (akMeta.getAccessKeyId().equals(akId)) {
				assertEquals("Inactive", akMeta.getStatus());
			}
		}
		// 修改密钥
		updateAccessKeyRequest.setStatus("Active");
		client.updateAccessKey(updateAccessKeyRequest);
		// 查询密钥
		listResult = client.listAccessKeys(listAccessKeysRequest);
		for (AccessKeyMetadata akMeta : listResult.getAccessKeyMetadata()) {
			if (akMeta.getAccessKeyId().equals(akId)) {
				assertEquals("Active", akMeta.getStatus());
			}
		}
		// 删除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		client.deleteAccessKey(deleteAccessKeyRequest);
	}

	/**
	 * 根用户，不指定UserName
	 */
	@Test
	public void updateAK_rootUser_ok_test() {
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		CreateAccessKeyResult akResult = rootClient.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(ownerName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 修改密钥
		UpdateAccessKeyRequest updateAccessKeyRequest = new UpdateAccessKeyRequest(akId, "Inactive");
		rootClient.updateAccessKey(updateAccessKeyRequest);
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		ListAccessKeysResult listResult = rootClient.listAccessKeys(listAccessKeysRequest);
		assertFalse(listResult.getIsTruncated());
		for (AccessKeyMetadata akMeta : listResult.getAccessKeyMetadata()) {
			if (akMeta.getAccessKeyId().equals(akId)) {
				assertEquals("Inactive", akMeta.getStatus());
			}
		}
		// 修改密钥
		updateAccessKeyRequest.setStatus("Active");
		rootClient.updateAccessKey(updateAccessKeyRequest);
		// 查询密钥
		listResult = rootClient.listAccessKeys(listAccessKeysRequest);
		for (AccessKeyMetadata akMeta : listResult.getAccessKeyMetadata()) {
			if (akMeta.getAccessKeyId().equals(akId)) {
				assertEquals("Active", akMeta.getStatus());
			}
		}
		// 删除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		rootClient.deleteAccessKey(deleteAccessKeyRequest);
	}

	@Test
	public void updateAK_invalidStatus_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 修改密钥
		UpdateAccessKeyRequest updateAccessKeyRequest = new UpdateAccessKeyRequest(akId, "Inactive1");
		updateAccessKeyRequest.setUserName(userName);
		try {
			client.updateAccessKey(updateAccessKeyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value 'Inactive1' at 'status' failed to satisfy constraint: Member must satisfy enum value set: [Active, Inactive]",
					e.getMessage());
		}
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		listAccessKeysRequest.setUserName(userName);
		ListAccessKeysResult listResult = client.listAccessKeys(listAccessKeysRequest);
		assertFalse(listResult.getIsTruncated());
		assertEquals(1, listResult.getAccessKeyMetadata().size());
		assertEquals("Active", listResult.getAccessKeyMetadata().get(0).getStatus());
		// 删除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void updateAK_statusNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 修改密钥
		UpdateAccessKeyRequest updateAccessKeyRequest = new UpdateAccessKeyRequest();
		updateAccessKeyRequest.setAccessKeyId(akId);
		updateAccessKeyRequest.setUserName(userName);
		try {
			client.updateAccessKey(updateAccessKeyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'status' failed to satisfy constraint: Member must not be null",
					e.getMessage());

		}
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		listAccessKeysRequest.setUserName(userName);
		ListAccessKeysResult listResult = client.listAccessKeys(listAccessKeysRequest);
		assertFalse(listResult.getIsTruncated());
		assertEquals(1, listResult.getAccessKeyMetadata().size());
		assertEquals("Active", listResult.getAccessKeyMetadata().get(0).getStatus());
		// 删除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void updateAK_akNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 修改密钥
		UpdateAccessKeyRequest updateAccessKeyRequest = new UpdateAccessKeyRequest();
		updateAccessKeyRequest.setStatus("Inactive");
		updateAccessKeyRequest.setUserName(userName);
		try {
			client.updateAccessKey(updateAccessKeyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'accessKeyId' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		listAccessKeysRequest.setUserName(userName);
		ListAccessKeysResult listResult = client.listAccessKeys(listAccessKeysRequest);
		assertFalse(listResult.getIsTruncated());
		assertEquals(1, listResult.getAccessKeyMetadata().size());
		assertEquals("Active", listResult.getAccessKeyMetadata().get(0).getStatus());
		// 删除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * Ak不合法,长度不够
	 */
	@Test
	public void updateAK_ak_invalid_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 修改密钥
		UpdateAccessKeyRequest updateAccessKeyRequest = new UpdateAccessKeyRequest();
		updateAccessKeyRequest.setStatus("Inactive");
		updateAccessKeyRequest.setAccessKeyId("123344");
		updateAccessKeyRequest.setUserName(userName);
		try {
			client.updateAccessKey(updateAccessKeyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '123344' at 'accessKeyId' failed to satisfy constraint: Member must have length greater than or equal to 16",
					e.getMessage());
		}
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		listAccessKeysRequest.setUserName(userName);
		ListAccessKeysResult listResult = client.listAccessKeys(listAccessKeysRequest);
		assertFalse(listResult.getIsTruncated());
		assertEquals(1, listResult.getAccessKeyMetadata().size());
		assertEquals("Active", listResult.getAccessKeyMetadata().get(0).getStatus());
		// 删除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * Ak不存在
	 */
	@Test
	public void updateAK_ak_notExist_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密钥
		CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest();
		createAccessKeyRequest.setUserName(userName);
		CreateAccessKeyResult akResult = client.createAccessKey(createAccessKeyRequest);
		AccessKey ak = akResult.getAccessKey();
		String akId = ak.getAccessKeyId();
		System.out.println(akId);
		assertEquals(userName, ak.getUserName());
		assertEquals("Active", ak.getStatus());
		// 修改密钥
		UpdateAccessKeyRequest updateAccessKeyRequest = new UpdateAccessKeyRequest();
		updateAccessKeyRequest.setStatus("Inactive");
		updateAccessKeyRequest.setAccessKeyId("26ece9ef2066415151a9");
		updateAccessKeyRequest.setUserName(userName);
		try {
			client.updateAccessKey(updateAccessKeyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The Access Key with id 26ece9ef2066415151a9 cannot be found.", e.getMessage());
		}
		// 查询密钥
		ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
		listAccessKeysRequest.setUserName(userName);
		ListAccessKeysResult listResult = client.listAccessKeys(listAccessKeysRequest);
		assertFalse(listResult.getIsTruncated());
		assertEquals(1, listResult.getAccessKeyMetadata().size());
		assertEquals("Active", listResult.getAccessKeyMetadata().get(0).getStatus());
		// 删除密钥
		DeleteAccessKeyRequest deleteAccessKeyRequest = new DeleteAccessKeyRequest(akId);
		deleteAccessKeyRequest.setUserName(userName);
		client.deleteAccessKey(deleteAccessKeyRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void createGetUpdateDeleteLoginProfile_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		System.out.println(profile.getPasswordResetRequired());
		System.out.println(profile.getCreateDate());
		assertEquals(userName, profile.getUserName());
		assertFalse(profile.getPasswordResetRequired());
		// 获取密码
		GetLoginProfileRequest getLoginProfileRequest = new GetLoginProfileRequest(userName);
		GetLoginProfileResult getResult = client.getLoginProfile(getLoginProfileRequest);
		LoginProfile loginProfile = getResult.getLoginProfile();
		assertEquals(userName, loginProfile.getUserName());
		assertFalse(loginProfile.getPasswordResetRequired());
		System.out.println("getProfile result----");
		System.out.println(loginProfile.getCreateDate());
		// 修改密码
		UpdateLoginProfileRequest updateLoginProfileRequest = new UpdateLoginProfileRequest(userName);
		updateLoginProfileRequest.setPassword("new12345678");
		client.updateLoginProfile(updateLoginProfileRequest);
		// 刪除密码
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(userName);
		client.deleteLoginProfile(deleteLoginProfileRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void createGetUpdateDeleteLoginProfile_ok_test2() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, password);
		createLoginProfileRequest.setPasswordResetRequired(true);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		System.out.println(profile.getPasswordResetRequired());
		System.out.println(profile.getCreateDate());
		assertEquals(userName, profile.getUserName());
		assertTrue(profile.getPasswordResetRequired());
		// 获取密码
		GetLoginProfileRequest getLoginProfileRequest = new GetLoginProfileRequest(userName);
		GetLoginProfileResult getResult = client.getLoginProfile(getLoginProfileRequest);
		LoginProfile loginProfile = getResult.getLoginProfile();
		assertEquals(userName, loginProfile.getUserName());
		assertTrue(loginProfile.getPasswordResetRequired());
		System.out.println("getProfile result----");
		System.out.println(loginProfile.getCreateDate());
		// 修改密码
		UpdateLoginProfileRequest updateLoginProfileRequest = new UpdateLoginProfileRequest(userName);
		updateLoginProfileRequest.setPassword("new12345678");
		updateLoginProfileRequest.setPasswordResetRequired(true);
		client.updateLoginProfile(updateLoginProfileRequest);
		// 刪除密码
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(userName);
		client.deleteLoginProfile(deleteLoginProfileRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void createLoginProfile_pdLength8_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "a1234567";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		assertEquals(userName, profile.getUserName());
		// 刪除密码
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(userName);
		client.deleteLoginProfile(deleteLoginProfileRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void createLoginProfile_pdLength128_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "a";
		for (int i = 1; i <= 127; i++) {
			password += 2;
		}
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		assertEquals(userName, profile.getUserName());
		// 刪除密碼
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(userName);
		client.deleteLoginProfile(deleteLoginProfileRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void createLoginProfile_password_invalid_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "12345678a中文!";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, password);
		try {
			client.createLoginProfile(createLoginProfileRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value at 'password' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\u0009\\u000A\\u000D\\u0020-\\u00FF]+",
					e.getMessage());
		}
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 缺少密码参数
	 */
	@Test
	public void createLoginProfile_passwdNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest();
		createLoginProfileRequest.setUserName(userName);
		try {
			client.createLoginProfile(createLoginProfileRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value at 'password' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 指定的用户不存在
	 */
	@Test
	public void createLoginProfile_user_notExist_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "12345678abc";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest();
		createLoginProfileRequest.setPassword(password);
		createLoginProfileRequest.setUserName("noUserxx");
		try {
			client.createLoginProfile(createLoginProfileRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name noUserxx cannot be found.", e.getMessage());
		}
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 缺少用户名参数
	 */
	@Test
	public void createLoginProfile_userNameNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "12345678abc";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest();
		createLoginProfileRequest.setPassword(password);
		try {
			client.createLoginProfile(createLoginProfileRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 用户密码已经存在
	 */
	@Test
	public void createLoginProfile_alreadyExists_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		System.out.println(profile.getPasswordResetRequired());
		System.out.println(profile.getCreateDate());
		assertEquals(userName, profile.getUserName());
		assertFalse(profile.getPasswordResetRequired());
		// 再次创建密码，失败
		try {
			client.createLoginProfile(createLoginProfileRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("EntityAlreadyExists", e.getErrorCode());
			assertEquals("Login Profile for user sdktestuser already exists.", e.getMessage());
		}
		// deleteLoginProfile
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(userName);
		client.deleteLoginProfile(deleteLoginProfileRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * getLoginProfile时，指定的user不存在
	 */
	@Test
	public void getLoginProfile_user_notExist_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, password);
		createLoginProfileRequest.setPasswordResetRequired(true);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		System.out.println(profile.getPasswordResetRequired());
		System.out.println(profile.getCreateDate());
		assertEquals(userName, profile.getUserName());
		assertTrue(profile.getPasswordResetRequired());
		// 获取密码
		GetLoginProfileRequest getLoginProfileRequest = new GetLoginProfileRequest("nouserXX");
		try {
			client.getLoginProfile(getLoginProfileRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name nouserXX cannot be found.", e.getMessage());
		}
		// 刪除密码
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(userName);
		client.deleteLoginProfile(deleteLoginProfileRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * getLoginProfile时，缺少userName参数
	 */
	@Test
	public void getLoginProfile_userNameNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, password);
		createLoginProfileRequest.setPasswordResetRequired(true);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		System.out.println(profile.getPasswordResetRequired());
		System.out.println(profile.getCreateDate());
		assertEquals(userName, profile.getUserName());
		assertTrue(profile.getPasswordResetRequired());
		// 获取密码
		GetLoginProfileRequest getLoginProfileRequest = new GetLoginProfileRequest();
		try {
			client.getLoginProfile(getLoginProfileRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 刪除密码
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(userName);
		client.deleteLoginProfile(deleteLoginProfileRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void changePassword_ok_test() {
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(subUser1, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		System.out.println(profile.getPasswordResetRequired());
		System.out.println(profile.getCreateDate());
		assertEquals(subUser1, profile.getUserName());
		assertFalse(profile.getPasswordResetRequired());
		// 修改密码
		String newPassword = "abcd123456";
		ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
		changePasswordRequest.setNewPassword(newPassword);
		changePasswordRequest.setOldPassword(password);
		client.changePassword(changePasswordRequest);
		// delete
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(subUser1);
		client.deleteLoginProfile(deleteLoginProfileRequest);
	}

	/**
	 * 更改密码时，旧密码不正确
	 */
	@Test
	public void changePassword_oldPasswdInvalid_fail_test() {
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(subUser1, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		System.out.println(profile.getPasswordResetRequired());
		System.out.println(profile.getCreateDate());
		assertEquals(subUser1, profile.getUserName());
		assertFalse(profile.getPasswordResetRequired());
		// 修改密码
		String newPassword = "abcd123456";
		ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
		changePasswordRequest.setNewPassword(newPassword);
		changePasswordRequest.setOldPassword("123456abc");
		try {
			client.changePassword(changePasswordRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(403, e.getStatusCode());
			assertEquals("AccessDenied", e.getErrorCode());
			assertEquals("The old password was incorrect.", e.getMessage());
		}
		changePasswordRequest.setOldPassword(password);
		client.changePassword(changePasswordRequest);
		// delete
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(subUser1);
		client.deleteLoginProfile(deleteLoginProfileRequest);
	}

	/**
	 * 更改密码时，和历史密码重复
	 */
	@Test
	public void changePassword_oldPasswd_length0_fail_test() {
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(subUser1, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		assertEquals(subUser1, profile.getUserName());
		assertFalse(profile.getPasswordResetRequired());
		// 修改密码
		String newPassword = "abcd123456";
		ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
		changePasswordRequest.setNewPassword(newPassword);
		changePasswordRequest.setOldPassword("");
		try {
			client.changePassword(changePasswordRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"2 validation errors detected: Value '' at 'oldPassword' failed to satisfy constraint: Member must have length greater than or equal to 8; Value at 'oldPassword' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\u0009\\u000A\\u000D\\u0020-\\u00FF]+",
					e.getMessage());
			System.out.println(e.getMessage());
		}
		changePasswordRequest.setOldPassword(password);
		client.changePassword(changePasswordRequest);
		// delete
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(subUser1);
		client.deleteLoginProfile(deleteLoginProfileRequest);
	}

	/**
	 * root用户调用ChangePassword方法
	 */
	@Test
	public void changePassword_root_fail_test() {
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(subUser1, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		assertEquals(subUser1, profile.getUserName());
		assertFalse(profile.getPasswordResetRequired());
		// 修改密码
		String newPassword = "abcd123456";
		ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
		changePasswordRequest.setNewPassword(newPassword);
		changePasswordRequest.setOldPassword(password);
		try {
			rootClient.changePassword(changePasswordRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(403, e.getStatusCode());
			assertEquals("AccessDenied", e.getErrorCode());
			assertEquals("Only IAM Users can change their own password.", e.getMessage());
		}
		client.changePassword(changePasswordRequest);
		// delete
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(subUser1);
		client.deleteLoginProfile(deleteLoginProfileRequest);
	}

	/**
	 * 账号2执行账号1的changePassword操作，报404
	 */
	@Test
	public void changePassword_client2_fail_test() {
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(subUser1, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		assertEquals(subUser1, profile.getUserName());
		assertFalse(profile.getPasswordResetRequired());
		// 修改密码
		String newPassword = "abcd123456";
		ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
		changePasswordRequest.setNewPassword(newPassword);
		changePasswordRequest.setOldPassword(password);
		try {
			client2.changePassword(changePasswordRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("Login Profile for User user2@oos.com cannot be found.", e.getMessage());
		}
		client.changePassword(changePasswordRequest);
		// delete
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(subUser1);
		client.deleteLoginProfile(deleteLoginProfileRequest);
	}

	/**
	 * 账号没有密码，changePassword报404
	 */
	@Test
	public void changePassword_noPasswd_fail_test() {
		String password = "abc123456";
		String newPassword = "abcd123456";
		ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
		changePasswordRequest.setNewPassword(newPassword);
		changePasswordRequest.setOldPassword(password);
		try {
			client.changePassword(changePasswordRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("Login Profile for User user1@oos.com cannot be found.", e.getMessage());
		}
	}

	/**
	 * 更改密码时，和历史密码重复
	 */
	@Test
	public void changePassword_oldNewSame_fail_test() {
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(subUser1, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		assertEquals(subUser1, profile.getUserName());
		assertFalse(profile.getPasswordResetRequired());
		// 修改密码
		String newPassword = password;
		ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
		changePasswordRequest.setNewPassword(newPassword);
		changePasswordRequest.setOldPassword(password);
		try {
			client.changePassword(changePasswordRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("PasswordPolicyViolation", e.getErrorCode());
			assertEquals("Policy constraint violation with password reuse prevention during password change.",
					e.getMessage());
		}
		// deletePassword
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(subUser1);
		client.deleteLoginProfile(deleteLoginProfileRequest);
	}

	/**
	 * 更改密码时，密码不符合密码策略
	 */
	@Test
	public void changePassword_notMatchPolicy_fail_test() {
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(subUser1, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		assertEquals(subUser1, profile.getUserName());
		assertFalse(profile.getPasswordResetRequired());
		// 创建密码策略
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setMinimumPasswordLength(15);
		client.updateAccountPasswordPolicy(updateRequest);
		// changePassword
		String newPassword = "abcd12345";
		ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
		changePasswordRequest.setNewPassword(newPassword);
		changePasswordRequest.setOldPassword(password);
		try {
			client.changePassword(changePasswordRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("PasswordPolicyViolation", e.getErrorCode());
			assertEquals("Password does not conform to the account password policy.", e.getMessage());
		}
		// deletePasswordPolicy
		DeleteAccountPasswordPolicyRequest deleteRequest = new DeleteAccountPasswordPolicyRequest();
		client.deleteAccountPasswordPolicy(deleteRequest);
		// deletePassword
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(subUser1);
		client.deleteLoginProfile(deleteLoginProfileRequest);
	}

	/**
	 * 更新密码时，缺少密码参数
	 */
	@Test
	public void updateLoginProfile_npPdParam_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		System.out.println(profile.getPasswordResetRequired());
		System.out.println(profile.getCreateDate());
		assertEquals(userName, profile.getUserName());
		assertFalse(profile.getPasswordResetRequired());
		// 修改密码
		UpdateLoginProfileRequest updateLoginProfileRequest = new UpdateLoginProfileRequest(userName);
		client.updateLoginProfile(updateLoginProfileRequest);
		// 刪除密码
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(userName);
		client.deleteLoginProfile(deleteLoginProfileRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 更新密码时，缺少用户名参数
	 */
	@Test
	public void updateLoginProfile_userNameNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		System.out.println(profile.getPasswordResetRequired());
		System.out.println(profile.getCreateDate());
		assertEquals(userName, profile.getUserName());
		assertFalse(profile.getPasswordResetRequired());
		// 修改密码
		UpdateLoginProfileRequest updateLoginProfileRequest = new UpdateLoginProfileRequest();
		updateLoginProfileRequest.setPassword("a12345678");
		try {
			client.updateLoginProfile(updateLoginProfileRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 刪除密码
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(userName);
		client.deleteLoginProfile(deleteLoginProfileRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 更新密码时，指定的用户不存在
	 */
	@Test
	public void updateLoginProfile_user_notExist_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		System.out.println(profile.getPasswordResetRequired());
		System.out.println(profile.getCreateDate());
		assertEquals(userName, profile.getUserName());
		assertFalse(profile.getPasswordResetRequired());
		// 修改密码
		UpdateLoginProfileRequest updateLoginProfileRequest = new UpdateLoginProfileRequest("noUserxx");
		updateLoginProfileRequest.setPassword("a12345678");
		try {
			client.updateLoginProfile(updateLoginProfileRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name noUserxx cannot be found.", e.getMessage());
		}
		// 刪除密码
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest(userName);
		client.deleteLoginProfile(deleteLoginProfileRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void deleteLoginProfile_user_notExist_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		System.out.println(profile.getPasswordResetRequired());
		System.out.println(profile.getCreateDate());
		assertEquals(userName, profile.getUserName());
		assertFalse(profile.getPasswordResetRequired());
		// 刪除密码
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest("noUserxxx");
		try {
			client.deleteLoginProfile(deleteLoginProfileRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name noUserxxx cannot be found.", e.getMessage());
		}
		deleteLoginProfileRequest.setUserName(userName);
		client.deleteLoginProfile(deleteLoginProfileRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void deleteLoginProfile_userNameNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result = client.createUser(cu);
		assertEquals(userName, result.getUser().getUserName());
		// 创建密码
		String password = "abc123456";
		CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest(userName, password);
		CreateLoginProfileResult profileResult = client.createLoginProfile(createLoginProfileRequest);
		LoginProfile profile = profileResult.getLoginProfile();
		System.out.println(profile.getPasswordResetRequired());
		System.out.println(profile.getCreateDate());
		assertEquals(userName, profile.getUserName());
		assertFalse(profile.getPasswordResetRequired());
		// 刪除密码
		DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest();
		try {
			client.deleteLoginProfile(deleteLoginProfileRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		deleteLoginProfileRequest.setUserName(userName);
		client.deleteLoginProfile(deleteLoginProfileRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void createDeleteVirtualMFADevice_ok_test() {
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa1234";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		System.out.println(mfa.getBase32StringSeed());
		System.out.println(mfa.getQRCodePNG());
		System.out.println(mfa.getSerialNumber());
		assertNotNull(mfa.getBase32StringSeed());
		assertNotNull(mfa.getQRCodePNG());
		assertNotNull(mfa.getSerialNumber());
		String arn = mfa.getSerialNumber();
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(arn);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
	}

	/**
	 * mfaName不区分大小写，不可重复创建 大小写相同
	 */
	/**
	 * @Test public void createVirtualMFADevice_ok_test() { // 创建mfa
	 *       CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new
	 *       CreateVirtualMFADeviceRequest(); String name = "Mfa1234";
	 *       createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
	 *       CreateVirtualMFADeviceResult result =
	 *       client.createVirtualMFADevice(createVirtualMFADeviceRequest);
	 *       VirtualMFADevice mfa = result.getVirtualMFADevice();
	 *       System.out.println(mfa.getBase32StringSeed());
	 *       System.out.println(mfa.getQRCodePNG());
	 *       System.out.println(mfa.getSerialNumber());
	 *       assertNotNull(mfa.getBase32StringSeed());
	 *       assertNotNull(mfa.getQRCodePNG());
	 *       assertNotNull(mfa.getSerialNumber()); String arn =
	 *       mfa.getSerialNumber(); try {
	 *       client.createVirtualMFADevice(createVirtualMFADeviceRequest); fail(); }
	 *       catch (AmazonS3Exception e) { assertEquals(409, e.getStatusCode());
	 *       assertEquals("EntityAlreadyExists", e.getErrorCode()); } // 删除mfa
	 *       DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new
	 *       DeleteVirtualMFADeviceRequest();
	 *       deleteVirtualMFADeviceRequest.setSerialNumber(arn);
	 *       client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest); }
	 * 
	 *       /** mfaName不区分大小写，不可重复创建 大小写不同
	 */
	@Test
	public void createVirtualMFADevice_ok_test2() {
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "Mfa1234";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		System.out.println(mfa.getBase32StringSeed());
		System.out.println(mfa.getQRCodePNG());
		System.out.println(mfa.getSerialNumber());
		assertNotNull(mfa.getBase32StringSeed());
		assertNotNull(mfa.getQRCodePNG());
		assertNotNull(mfa.getSerialNumber());
		String arn = mfa.getSerialNumber();
		createVirtualMFADeviceRequest.setVirtualMFADeviceName("mfa1234");
		try {
			client.createVirtualMFADevice(createVirtualMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("EntityAlreadyExists", e.getErrorCode());
		}
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(arn);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
	}

	@Test
	public void createVirtualMFADevice_nameLength0_fail_test2() {
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		try {
			client.createVirtualMFADevice(createVirtualMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'virtualMFADeviceName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
					e.getMessage());
		}
	}

	@Test
	public void createVirtualMFADevice_nameLength1_ok_test() {
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "a";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		System.out.println(mfa.getBase32StringSeed());
		System.out.println(mfa.getQRCodePNG());
		System.out.println(mfa.getSerialNumber());
		assertNotNull(mfa.getBase32StringSeed());
		assertNotNull(mfa.getQRCodePNG());
		assertNotNull(mfa.getSerialNumber());
		String arn = mfa.getSerialNumber();
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(arn);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
	}

	@Test
	public void createVirtualMFADevice_nameLength128_ok_test() {
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "";
		for (int i = 1; i <= 128; i++) {
			name += 1;
		}
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		System.out.println(mfa.getBase32StringSeed());
		System.out.println(mfa.getQRCodePNG());
		System.out.println(mfa.getSerialNumber());
		assertNotNull(mfa.getBase32StringSeed());
		assertNotNull(mfa.getQRCodePNG());
		assertNotNull(mfa.getSerialNumber());
		String arn = mfa.getSerialNumber();
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(arn);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
	}

	@Test
	public void createVirtualMFADevice_nameLength129_fail_test() {
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "";
		for (int i = 1; i <= 129; i++) {
			name += 1;
		}
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		try {
			client.createVirtualMFADevice(createVirtualMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals("1 validation error detected: Value '" + name
					+ "' at 'virtualMFADeviceName' failed to satisfy constraint: Member must have length less than or equal to 128",
					e.getMessage());
		}
	}

	@Test
	public void createVirtualMFADevice_specialCharater_ok_test() {
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "12Ab3_+=,.@-";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		System.out.println(mfa.getBase32StringSeed());
		System.out.println(mfa.getQRCodePNG());
		System.out.println(mfa.getSerialNumber());
		assertNotNull(mfa.getBase32StringSeed());
		assertNotNull(mfa.getQRCodePNG());
		assertNotNull(mfa.getSerialNumber());
		String arn = mfa.getSerialNumber();
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(arn);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
	}

	@Test
	public void createVirtualMFADevice_nameContainsBlank_fail_test() {
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "aabb cc dd";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		try {
			client.createVirtualMFADevice(createVirtualMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'virtualMFADeviceName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
					e.getMessage());
		}
	}

	@Test
	public void createVirtualMFADevice_nameContainsChinese_fail_test() {
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "aabbccdd中文";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		try {
			client.createVirtualMFADevice(createVirtualMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'virtualMFADeviceName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
					e.getMessage());
		}
	}

	@Test
	public void createVirtualMFADevice_specialCharater_fail_test() {
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "@#$%!";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		try {
			client.createVirtualMFADevice(createVirtualMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'virtualMFADeviceName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
					e.getMessage());
		}
	}

	/**
	 * 缺少参数mfaName
	 */
	@Test
	public void createVirtualMFADevice_mfaNameNull_fail_test() {
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		try {
			client.createVirtualMFADevice(createVirtualMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'virtualMFADeviceName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
	}

	/**
	 * 指定的SerialNumber不存在
	 */
	@Test
	public void deleteVirtualMFADevice_invalidSerialNumber_fail_test() {
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa1";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		System.out.println(mfa.getBase32StringSeed());
		System.out.println(mfa.getQRCodePNG());
		System.out.println(mfa.getSerialNumber());
		assertNotNull(mfa.getBase32StringSeed());
		assertNotNull(mfa.getQRCodePNG());
		assertNotNull(mfa.getSerialNumber());
		String arn = mfa.getSerialNumber();
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber("arn:ctyun:iam::34e5k5ig79cjf:mfa/*");
		try {
			client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals("1 validation error detected: The specified value for 'serialNumber' is invalid",
					e.getMessage());
		}
		deleteVirtualMFADeviceRequest.setSerialNumber(arn);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
	}

	/**
	 * 缺少SerialNumber参数
	 */
	@Test
	public void deleteVirtualMFADevice_serialNumberNull_fail_test() {
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "abcdefg";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		System.out.println(mfa.getBase32StringSeed());
		System.out.println(mfa.getQRCodePNG());
		System.out.println(mfa.getSerialNumber());
		assertNotNull(mfa.getBase32StringSeed());
		assertNotNull(mfa.getQRCodePNG());
		assertNotNull(mfa.getSerialNumber());
		String arn = mfa.getSerialNumber();
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		try {
			client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'serialNumber' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		deleteVirtualMFADeviceRequest.setSerialNumber(arn);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
	}

	@Test
	public void enableDeactivateMFADevice_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "abcdefg2";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, codesPair.first(),
				codesPair.second());
		client.enableMFADevice(enableMFADeviceRequest);
		// 解绑
		DeactivateMFADeviceRequest deactivateMFADeviceRequest = new DeactivateMFADeviceRequest(userName, number);
		client.deactivateMFADevice(deactivateMFADeviceRequest);
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);

	}

	/**
	 * ARN不区分大小写 全部小写
	 */
	@Test
	public void enableMFADevice_arnLowerCase_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfatest";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number.toLowerCase(),
				codesPair.first(), codesPair.second());
		client.enableMFADevice(enableMFADeviceRequest);
		// 解绑
		DeactivateMFADeviceRequest deactivateMFADeviceRequest = new DeactivateMFADeviceRequest(userName, number);
		client.deactivateMFADevice(deactivateMFADeviceRequest);
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);

	}

	/**
	 * ARN不区分大小写 全部大写
	 */
	@Test
	public void enableMFADevice_arnUpperCase_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "abcdefg2";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number.toUpperCase(),
				codesPair.first(), codesPair.second());
		client.enableMFADevice(enableMFADeviceRequest);
		// 解绑
		DeactivateMFADeviceRequest deactivateMFADeviceRequest = new DeactivateMFADeviceRequest(userName, number);
		client.deactivateMFADevice(deactivateMFADeviceRequest);
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);

	}

	@Test
	public void enableMFADevice_invalidCode1_fail_test1() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa01";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, "x23456",
				codesPair.second());
		try {
			client.enableMFADevice(enableMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'authenticationCode1' is invalid. It must be a six-digit decimal number",
					e.getMessage());
		}
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void enableMFADevice_invalidCode1_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa01";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, "123456",
				codesPair.second());
		try {
			client.enableMFADevice(enableMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(403, e.getStatusCode());
			assertEquals("InvalidAuthenticationCode", e.getErrorCode());
			assertEquals("Authentication code for device is not valid.", e.getMessage());
		}
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void enableMFADevice_invalidCode2_fail_test1() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa01";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, codesPair.first(),
				"A23456");
		try {
			client.enableMFADevice(enableMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'authenticationCode2' is invalid. It must be a six-digit decimal number",
					e.getMessage());
		}
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void enableMFADevice_invalidCode2_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa01";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, codesPair.first(),
				"123456");
		try {
			client.enableMFADevice(enableMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(403, e.getStatusCode());
			assertEquals("InvalidAuthenticationCode", e.getErrorCode());
			assertEquals("Authentication code for device is not valid.", e.getMessage());
		}
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void enableMFADevice_SerialNumber_notExist_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa01";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName,
				"TT6VXHO7NYP4S3DI2EBWM4R5I4BID2YMMT5SLUIKYO4MTE7VNARISZVP4UW7NCJA", codesPair.first(),
				codesPair.second());
		try {
			client.enableMFADevice(enableMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals(
					"VirtualMFADevice with serial number TT6VXHO7NYP4S3DI2EBWM4R5I4BID2YMMT5SLUIKYO4MTE7VNARISZVP4UW7NCJA does not exist.",
					e.getMessage());
		}
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 指定用户不存在
	 */
	@Test
	public void enableMFADevice_user_notExist_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa01";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest("nouserXX", number,
				codesPair.first(), codesPair.second());
		try {
			client.enableMFADevice(enableMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name nouserXX cannot be found.", e.getMessage());
		}
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 缺少userName参数
	 */
	@Test
	public void enableMFADevice_userNameNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa01";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest();
		enableMFADeviceRequest.setAuthenticationCode1(codesPair.first());
		enableMFADeviceRequest.setAuthenticationCode2(codesPair.second());
		enableMFADeviceRequest.setSerialNumber(number);
		try {
			client.enableMFADevice(enableMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 缺少code1参数
	 */
	@Test
	public void enableMFADevice_code1Null_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa01";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest();
		enableMFADeviceRequest.setAuthenticationCode2(codesPair.second());
		enableMFADeviceRequest.setSerialNumber(number);
		enableMFADeviceRequest.setUserName(userName);
		try {
			client.enableMFADevice(enableMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'authenticationCode1' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 缺少code2参数
	 */
	@Test
	public void enableMFADevice_code2Null_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa01";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest();
		enableMFADeviceRequest.setAuthenticationCode1(codesPair.first());
		enableMFADeviceRequest.setSerialNumber(number);
		enableMFADeviceRequest.setUserName(userName);
		try {
			client.enableMFADevice(enableMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'authenticationCode2' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 缺少SerialNumber参数
	 */
	@Test
	public void enableMFADevice_serialNumberNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa01";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest();
		enableMFADeviceRequest.setAuthenticationCode1(codesPair.first());
		enableMFADeviceRequest.setAuthenticationCode2(codesPair.second());
		enableMFADeviceRequest.setUserName(userName);
		try {
			client.enableMFADevice(enableMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'serialNumber' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 
	 * 解绑mfa时，指定的arn不存在
	 */
	@Test
	public void deactivateMFADevice_serialNumber_notExist_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa001";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, codesPair.first(),
				codesPair.second());
		client.enableMFADevice(enableMFADeviceRequest);
		// 解绑失败
		DeactivateMFADeviceRequest deactivateMFADeviceRequest = new DeactivateMFADeviceRequest();
		deactivateMFADeviceRequest.setSerialNumber("CC6VXHO7NYP4S3DI2EBWM4R5I4BID2YMMT5SLUIKYO4MTE7VNARISZVP4UW7NCJA");
		deactivateMFADeviceRequest.setUserName(userName);
		try {
			client.deactivateMFADevice(deactivateMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals(
					"VirtualMFADevice with serial number CC6VXHO7NYP4S3DI2EBWM4R5I4BID2YMMT5SLUIKYO4MTE7VNARISZVP4UW7NCJA does not exist.",
					e.getMessage());
		}
		// 解绑
		deactivateMFADeviceRequest.setSerialNumber(number);
		client.deactivateMFADevice(deactivateMFADeviceRequest);
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 
	 * 解绑mfa时，不指定arn
	 */
	@Test
	public void deactivateMFADevice_serialNumberNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa001";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, codesPair.first(),
				codesPair.second());
		client.enableMFADevice(enableMFADeviceRequest);
		// 解绑失败
		DeactivateMFADeviceRequest deactivateMFADeviceRequest = new DeactivateMFADeviceRequest();
		deactivateMFADeviceRequest.setUserName(userName);
		try {
			client.deactivateMFADevice(deactivateMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'serialNumber' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 解绑
		deactivateMFADeviceRequest.setSerialNumber(number);
		client.deactivateMFADevice(deactivateMFADeviceRequest);
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 
	 * 解绑mfa时，指定的user不存在
	 */
	@Test
	public void deactivateMFADevice_user_notExist_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa001";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, codesPair.first(),
				codesPair.second());
		client.enableMFADevice(enableMFADeviceRequest);
		// 解绑失败
		DeactivateMFADeviceRequest deactivateMFADeviceRequest = new DeactivateMFADeviceRequest();
		deactivateMFADeviceRequest.setSerialNumber(number);
		deactivateMFADeviceRequest.setUserName("noUserxx");
		try {
			client.deactivateMFADevice(deactivateMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name noUserxx cannot be found.", e.getMessage());
		}
		// 解绑
		deactivateMFADeviceRequest.setUserName(userName);
		client.deactivateMFADevice(deactivateMFADeviceRequest);
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 
	 * 解绑mfa时，缺少userName参数
	 */
	@Test
	public void deactivateMFADevice_userNameNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult result2 = client.createUser(cu);
		assertEquals(userName, result2.getUser().getUserName());
		// 创建mfa
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa001";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 给用户绑定mfa
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, codesPair.first(),
				codesPair.second());
		System.out.println("---------------");
		System.out.println(codesPair.first());
		System.out.println(codesPair.second());
		client.enableMFADevice(enableMFADeviceRequest);
		// 解绑失败
		DeactivateMFADeviceRequest deactivateMFADeviceRequest = new DeactivateMFADeviceRequest();
		deactivateMFADeviceRequest.setSerialNumber(number);
		try {
			client.deactivateMFADevice(deactivateMFADeviceRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 解绑
		deactivateMFADeviceRequest.setUserName(userName);
		client.deactivateMFADevice(deactivateMFADeviceRequest);
		// 删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		// 删除用户
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	
	@Test
	public void listVirtualMFADevices_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult userResult = client.createUser(cu);
		assertEquals(userName, userResult.getUser().getUserName());
		// 创建mfa1
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa1";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 创建mfa2
		String name2 = "mfa2";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name2);
		result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa2 = result.getVirtualMFADevice();
		String number2 = mfa2.getSerialNumber();
		String base32StringSeed2 = mfa2.getBase32StringSeedStr();
		System.out.println(base32StringSeed2);
		// 为用户绑定mfa1
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, codesPair.first(),
				codesPair.second());
		client.enableMFADevice(enableMFADeviceRequest);
		// listmfa
		ListVirtualMFADevicesRequest listVirtualMFADevicesRequest = new ListVirtualMFADevicesRequest();
		ListVirtualMFADevicesResult listResult = client.listVirtualMFADevices(listVirtualMFADevicesRequest);
		List<VirtualMFADevice> mfaDevices = listResult.getVirtualMFADevices();
		assertEquals(2, mfaDevices.size());
		for(VirtualMFADevice mfaDevice: mfaDevices) {
			if(null != mfaDevice.getUser().getArn()) {
				System.out.println(mfaDevice.getSerialNumber());
				User user = mfaDevice.getUser();
				System.out.println(user.getArn());
				System.out.println(user.getUserId());
				System.out.println(user.getUserName());
				assertEquals(userName, user.getUserName());
			}else {
				System.out.println(mfaDevice.getSerialNumber());
			}
		}
		//用户解绑mfa
		DeactivateMFADeviceRequest deactivateMFADeviceRequest = new DeactivateMFADeviceRequest(userName,number);
		client.deactivateMFADevice(deactivateMFADeviceRequest);
		//deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		//删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		deleteVirtualMFADeviceRequest.setSerialNumber(number2);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
	}
	
	@Test
	public void listVirtualMFADevices_assignmentStatus_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult userResult = client.createUser(cu);
		assertEquals(userName, userResult.getUser().getUserName());
		// 创建mfa1
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa1";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 创建mfa2
		String name2 = "mfa2";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name2);
		result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa2 = result.getVirtualMFADevice();
		String number2 = mfa2.getSerialNumber();
		String base32StringSeed2 = mfa2.getBase32StringSeedStr();
		System.out.println(base32StringSeed2);
		// 为用户绑定mfa1
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, codesPair.first(),
				codesPair.second());
		client.enableMFADevice(enableMFADeviceRequest);
		// listmfa
		ListVirtualMFADevicesRequest listVirtualMFADevicesRequest = new ListVirtualMFADevicesRequest();
		listVirtualMFADevicesRequest.setAssignmentStatus("Assigned");
		ListVirtualMFADevicesResult listResult = client.listVirtualMFADevices(listVirtualMFADevicesRequest);
		List<VirtualMFADevice> mfaDevices = listResult.getVirtualMFADevices();
		assertEquals(1, mfaDevices.size());
		System.out.println(mfaDevices.get(0).getSerialNumber());
		User user = mfaDevices.get(0).getUser();
		System.out.println(user.getArn());
		System.out.println(user.getUserId());
		System.out.println(user.getUserName());
		assertEquals(userName, user.getUserName());
		//listmfa
		listVirtualMFADevicesRequest.setAssignmentStatus("Unassigned");
		listResult = client.listVirtualMFADevices(listVirtualMFADevicesRequest);
		mfaDevices = listResult.getVirtualMFADevices();
		assertEquals(1, mfaDevices.size());
		System.out.println(mfaDevices.get(0).getSerialNumber());
		assertNull(mfaDevices.get(0).getUser().getArn());
		// listmfa
		listVirtualMFADevicesRequest.setAssignmentStatus("Any");
		listResult = client.listVirtualMFADevices(listVirtualMFADevicesRequest);
		mfaDevices = listResult.getVirtualMFADevices();
		assertEquals(2, mfaDevices.size());
		//用户解绑mfa
		DeactivateMFADeviceRequest deactivateMFADeviceRequest = new DeactivateMFADeviceRequest(userName,number);
		client.deactivateMFADevice(deactivateMFADeviceRequest);
		//deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		//删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		deleteVirtualMFADeviceRequest.setSerialNumber(number2);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
	}
	
	/**
	 * AssignmentStatus为无效值
	 */
	@Test
	public void listVirtualMFADevices_assignmentStatus_invalid_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult userResult = client.createUser(cu);
		assertEquals(userName, userResult.getUser().getUserName());
		// 创建mfa1
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa1";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 创建mfa2
		String name2 = "mfa2";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name2);
		result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa2 = result.getVirtualMFADevice();
		String number2 = mfa2.getSerialNumber();
		String base32StringSeed2 = mfa2.getBase32StringSeedStr();
		System.out.println(base32StringSeed2);
		// 为用户绑定mfa1
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, codesPair.first(),
				codesPair.second());
		client.enableMFADevice(enableMFADeviceRequest);
		// listmfa
		ListVirtualMFADevicesRequest listVirtualMFADevicesRequest = new ListVirtualMFADevicesRequest();
		listVirtualMFADevicesRequest.setAssignmentStatus("Any1");
		
		try {
			client.listVirtualMFADevices(listVirtualMFADevicesRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value 'Any1' at 'assignmentStatus' failed to satisfy constraint: Member must satisfy enum value set: [Unassigned, Any, Assigned]",
					e.getMessage());
		}
		//用户解绑mfa
		DeactivateMFADeviceRequest deactivateMFADeviceRequest = new DeactivateMFADeviceRequest(userName,number);
		client.deactivateMFADevice(deactivateMFADeviceRequest);
		//deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		//删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		deleteVirtualMFADeviceRequest.setSerialNumber(number2);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
	}
	
	@Test
	public void listVirtualMFADevices_maxItems1_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult userResult = client.createUser(cu);
		assertEquals(userName, userResult.getUser().getUserName());
		// 创建mfa1
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa1";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 创建mfa2
		String name2 = "mfa2";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name2);
		result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa2 = result.getVirtualMFADevice();
		String number2 = mfa2.getSerialNumber();
		String base32StringSeed2 = mfa2.getBase32StringSeedStr();
		System.out.println(base32StringSeed2);
		// 为用户绑定mfa1
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, codesPair.first(),
				codesPair.second());
		client.enableMFADevice(enableMFADeviceRequest);
		// listmfa
		ListVirtualMFADevicesRequest listVirtualMFADevicesRequest = new ListVirtualMFADevicesRequest();
		listVirtualMFADevicesRequest.setMaxItems(1);
		ListVirtualMFADevicesResult listResult = client.listVirtualMFADevices(listVirtualMFADevicesRequest);
		List<VirtualMFADevice> mfaDevices = listResult.getVirtualMFADevices();
		assertEquals(1, mfaDevices.size());
		System.out.println(listResult.getMarker());
		assertEquals(accountId+"|mfa1", listResult.getMarker());
		//用户解绑mfa
		DeactivateMFADeviceRequest deactivateMFADeviceRequest = new DeactivateMFADeviceRequest(userName,number);
		client.deactivateMFADevice(deactivateMFADeviceRequest);
		//deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		//删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		deleteVirtualMFADeviceRequest.setSerialNumber(number2);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
	}
	
	/**
	 * 如果请求中没有指定用户，那么OOS根据发送请求的access key id来判断是哪个用户。
	 */
	@Test
	public void listMFADevices_noMfa_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult userResult = client.createUser(cu);
		assertEquals(userName, userResult.getUser().getUserName());
		// 创建mfa1
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa1";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 创建mfa2
		String name2 = "mfa2";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name2);
		result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa2 = result.getVirtualMFADevice();
		String number2 = mfa2.getSerialNumber();
		String base32StringSeed2 = mfa2.getBase32StringSeedStr();
		System.out.println(base32StringSeed2);
		// 为用户绑定mfa1
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, codesPair.first(),
				codesPair.second());
		client.enableMFADevice(enableMFADeviceRequest);
		// listmfa
		ListMFADevicesRequest listMFADevicesRequest = new ListMFADevicesRequest();
		ListMFADevicesResult listResult = client.listMFADevices(listMFADevicesRequest);
		List<MFADevice> mfaDevices = listResult.getMFADevices();
		assertEquals(0, mfaDevices.size()); //未指定userName
		//用户解绑mfa
		DeactivateMFADeviceRequest deactivateMFADeviceRequest = new DeactivateMFADeviceRequest(userName,number);
		client.deactivateMFADevice(deactivateMFADeviceRequest);
		//deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		//删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		deleteVirtualMFADeviceRequest.setSerialNumber(number2);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
	}
	
	@Test
	public void listMFADevices_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult userResult = client.createUser(cu);
		assertEquals(userName, userResult.getUser().getUserName());
		// 创建mfa1
		CreateVirtualMFADeviceRequest createVirtualMFADeviceRequest = new CreateVirtualMFADeviceRequest();
		String name = "mfa1";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name);
		CreateVirtualMFADeviceResult result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa = result.getVirtualMFADevice();
		String number = mfa.getSerialNumber();
		String base32StringSeed = mfa.getBase32StringSeedStr();
		System.out.println(base32StringSeed);
		// 创建mfa2
		String name2 = "mfa2";
		createVirtualMFADeviceRequest.setVirtualMFADeviceName(name2);
		result = client.createVirtualMFADevice(createVirtualMFADeviceRequest);
		VirtualMFADevice mfa2 = result.getVirtualMFADevice();
		String number2 = mfa2.getSerialNumber();
		String base32StringSeed2 = mfa2.getBase32StringSeedStr();
		System.out.println(base32StringSeed2);
		// 为用户绑定mfa1
		Pair<String, String> codesPair = CreateIdentifyingCode(base32StringSeed);
		EnableMFADeviceRequest enableMFADeviceRequest = new EnableMFADeviceRequest(userName, number, codesPair.first(),
				codesPair.second());
		client.enableMFADevice(enableMFADeviceRequest);
		// listmfa
		ListMFADevicesRequest listMFADevicesRequest = new ListMFADevicesRequest();
		listMFADevicesRequest.setUserName(userName);
		ListMFADevicesResult listResult = client.listMFADevices(listMFADevicesRequest);
		List<MFADevice> mfaDevices = listResult.getMFADevices();
		assertEquals(1, mfaDevices.size());
		assertEquals(userName, mfaDevices.get(0).getUserName());
		assertEquals(number, mfaDevices.get(0).getSerialNumber());
		//用户解绑mfa
		DeactivateMFADeviceRequest deactivateMFADeviceRequest = new DeactivateMFADeviceRequest(userName,number);
		client.deactivateMFADevice(deactivateMFADeviceRequest);
		//deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		//删除mfa
		DeleteVirtualMFADeviceRequest deleteVirtualMFADeviceRequest = new DeleteVirtualMFADeviceRequest();
		deleteVirtualMFADeviceRequest.setSerialNumber(number);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
		deleteVirtualMFADeviceRequest.setSerialNumber(number2);
		client.deleteVirtualMFADevice(deleteVirtualMFADeviceRequest);
	}
	

	@Test
	public void updateGetDelAccountPasswordPolicy_ok_test() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setAllowUsersToChangePassword(true);
		updateRequest.setHardExpiry(true);
		updateRequest.setMaxPasswordAge(0);
		updateRequest.setMinimumPasswordLength(10);
		updateRequest.setPasswordReusePrevention(2);
		updateRequest.setRequireLowercaseCharacters(true);
		updateRequest.setRequireUppercaseCharacters(true);
		updateRequest.setRequireNumbers(true);
		updateRequest.setRequireSymbols(true);
		client.updateAccountPasswordPolicy(updateRequest);
		// get
		GetAccountPasswordPolicyRequest getRequest = new GetAccountPasswordPolicyRequest();
		GetAccountPasswordPolicyResult getResult = client.getAccountPasswordPolicy(getRequest);
		PasswordPolicy policy = getResult.getPasswordPolicy();
		assertTrue(policy.getAllowUsersToChangePassword());
		assertTrue(policy.getHardExpiry());
		assertEquals(0, policy.getMaxPasswordAge().intValue());
		assertEquals(10, policy.getMinimumPasswordLength().intValue());
		assertEquals(2, policy.getPasswordReusePrevention().intValue());
		assertTrue(policy.getRequireLowercaseCharacters());
		assertTrue(policy.getRequireUppercaseCharacters());
		assertTrue(policy.getRequireNumbers());
		assertTrue(policy.getRequireSymbols());
		// delete
		DeleteAccountPasswordPolicyRequest deleteRequest = new DeleteAccountPasswordPolicyRequest();
		client.deleteAccountPasswordPolicy(deleteRequest);
		// get 默认密码
		getResult = client.getAccountPasswordPolicy(getRequest);
		policy = getResult.getPasswordPolicy();
		assertTrue(policy.getAllowUsersToChangePassword());
		assertFalse(policy.getHardExpiry());
		assertEquals(0, policy.getMaxPasswordAge().intValue());
		assertEquals(8, policy.getMinimumPasswordLength().intValue());
		assertEquals(0, policy.getPasswordReusePrevention().intValue());
		assertTrue(policy.getRequireLowercaseCharacters());
		assertFalse(policy.getRequireUppercaseCharacters());
		assertTrue(policy.getRequireNumbers());
		assertFalse(policy.getRequireSymbols());
	}

	@Test
	public void updateGetDelAccountPasswordPolicy_ok_test2() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setAllowUsersToChangePassword(false);
		updateRequest.setHardExpiry(false);
		updateRequest.setMaxPasswordAge(10);
		updateRequest.setMinimumPasswordLength(11);
		updateRequest.setPasswordReusePrevention(3);
		updateRequest.setRequireLowercaseCharacters(false);
		updateRequest.setRequireNumbers(false);
		updateRequest.setRequireSymbols(false);
		updateRequest.setRequireUppercaseCharacters(false);
		client.updateAccountPasswordPolicy(updateRequest);
		// get
		GetAccountPasswordPolicyRequest getRequest = new GetAccountPasswordPolicyRequest();
		GetAccountPasswordPolicyResult getResult = client.getAccountPasswordPolicy(getRequest);
		PasswordPolicy policy = getResult.getPasswordPolicy();
		assertFalse(policy.getAllowUsersToChangePassword());
		assertFalse(policy.getHardExpiry());
		assertEquals(10, policy.getMaxPasswordAge().intValue());
		assertEquals(11, policy.getMinimumPasswordLength().intValue());
		assertEquals(3, policy.getPasswordReusePrevention().intValue());
		assertFalse(policy.getRequireLowercaseCharacters());
		assertFalse(policy.getRequireUppercaseCharacters());
		assertFalse(policy.getRequireNumbers());
		assertFalse(policy.getRequireSymbols());
		// delete
		DeleteAccountPasswordPolicyRequest deleteRequest = new DeleteAccountPasswordPolicyRequest();
		client.deleteAccountPasswordPolicy(deleteRequest);
	}

	/**
	 * update不带参数，密码策略存在，只是和默认密码策略相同。
	 */
	@Test
	public void updateGetDelAccountPasswordPolicy_ok_test3() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		client.updateAccountPasswordPolicy(updateRequest);
		// get
		GetAccountPasswordPolicyRequest getRequest = new GetAccountPasswordPolicyRequest();
		GetAccountPasswordPolicyResult getResult = client.getAccountPasswordPolicy(getRequest);
		PasswordPolicy policy = getResult.getPasswordPolicy();
		assertTrue(policy.getAllowUsersToChangePassword());
		assertFalse(policy.getHardExpiry());
		assertEquals(0, policy.getMaxPasswordAge().intValue());
		assertEquals(8, policy.getMinimumPasswordLength().intValue());
		assertEquals(0, policy.getPasswordReusePrevention().intValue());
		assertTrue(policy.getRequireLowercaseCharacters());
		assertFalse(policy.getRequireUppercaseCharacters());
		assertTrue(policy.getRequireNumbers());
		assertFalse(policy.getRequireSymbols());
		// delete
		DeleteAccountPasswordPolicyRequest deleteRequest = new DeleteAccountPasswordPolicyRequest();
		client.deleteAccountPasswordPolicy(deleteRequest);
		// get 默认密码
		getResult = client.getAccountPasswordPolicy(getRequest);
		policy = getResult.getPasswordPolicy();
		assertTrue(policy.getAllowUsersToChangePassword());
		assertFalse(policy.getHardExpiry());
		assertEquals(0, policy.getMaxPasswordAge().intValue());
		assertEquals(8, policy.getMinimumPasswordLength().intValue());
		assertEquals(0, policy.getPasswordReusePrevention().intValue());
		assertTrue(policy.getRequireLowercaseCharacters());
		assertFalse(policy.getRequireUppercaseCharacters());
		assertTrue(policy.getRequireNumbers());
		assertFalse(policy.getRequireSymbols());
	}

	/**
	 * 连续两次update
	 */
	@Test
	public void updateAccountPasswordPolicy_ok_test() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		client.updateAccountPasswordPolicy(updateRequest);
		client.updateAccountPasswordPolicy(updateRequest);
		// delete
		DeleteAccountPasswordPolicyRequest deleteRequest = new DeleteAccountPasswordPolicyRequest();
		client.deleteAccountPasswordPolicy(deleteRequest);
	}

	@Test
	public void updateAccountPasswordPolicy_maxPasswordAge1095_ok_test() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setMaxPasswordAge(1095);
		client.updateAccountPasswordPolicy(updateRequest);
		// delete
		DeleteAccountPasswordPolicyRequest deleteRequest = new DeleteAccountPasswordPolicyRequest();
		client.deleteAccountPasswordPolicy(deleteRequest);
	}

	@Test
	public void updateAccountPasswordPolicy_maxPasswordAge_fail_test() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setMaxPasswordAge(-1);
		try {
			client.updateAccountPasswordPolicy(updateRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '-1' at 'maxPasswordAge' failed to satisfy constraint: Member must have value greater than or equal to 0",
					e.getMessage());
		}
	}

	@Test
	public void updateAccountPasswordPolicy_maxPasswordAge_fail_test2() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setMaxPasswordAge(1096);
		try {
			client.updateAccountPasswordPolicy(updateRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '1096' at 'maxPasswordAge' failed to satisfy constraint: Member must have length less than or equal to 1095",
					e.getMessage());
		}
	}

	@Test
	public void updateAccountPasswordPolicy_minimumPasswordLength7_fail_test() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setMinimumPasswordLength(7);
		try {
			client.updateAccountPasswordPolicy(updateRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '7' at 'minimumPasswordLength' failed to satisfy constraint: Member must have value greater than or equal to 8",
					e.getMessage());
		}
	}

	@Test
	public void updateAccountPasswordPolicy_minimumPasswordLength129_fail_test() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setMinimumPasswordLength(129);
		try {
			client.updateAccountPasswordPolicy(updateRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '129' at 'minimumPasswordLength' failed to satisfy constraint: Member must have length less than or equal to 128",
					e.getMessage());
		}
	}

	@Test
	public void updateAccountPasswordPolicy_minimumPasswordLength128_ok_test() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setMinimumPasswordLength(128);
		client.updateAccountPasswordPolicy(updateRequest);
		// delete
		DeleteAccountPasswordPolicyRequest deleteRequest = new DeleteAccountPasswordPolicyRequest();
		client.deleteAccountPasswordPolicy(deleteRequest);
	}

	@Test
	public void updateAccountPasswordPolicy_passwordReusePrevention_fail_test1() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setPasswordReusePrevention(-1);
		try {
			client.updateAccountPasswordPolicy(updateRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '-1' at 'passwordReusePrevention' failed to satisfy constraint: Member must have value greater than or equal to 0",
					e.getMessage());
		}
	}

	@Test
	public void updateAccountPasswordPolicy_passwordReusePrevention_fail_test2() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setPasswordReusePrevention(25);
		try {
			client.updateAccountPasswordPolicy(updateRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '25' at 'passwordReusePrevention' failed to satisfy constraint: Member must have length less than or equal to 24",
					e.getMessage());
		}
	}

	@Test
	public void updateAccountPasswordPolicy_passwordReusePrevention0_ok_test() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setPasswordReusePrevention(0);
		client.updateAccountPasswordPolicy(updateRequest);
		// delete
		DeleteAccountPasswordPolicyRequest deleteRequest = new DeleteAccountPasswordPolicyRequest();
		client.deleteAccountPasswordPolicy(deleteRequest);
	}

	@Test
	public void updateAccountPasswordPolicy_passwordReusePrevention24_ok_test() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setPasswordReusePrevention(24);
		client.updateAccountPasswordPolicy(updateRequest);
		// delete
		DeleteAccountPasswordPolicyRequest deleteRequest = new DeleteAccountPasswordPolicyRequest();
		client.deleteAccountPasswordPolicy(deleteRequest);
	}

	/**
	 * 密码策略不存在，删除报404
	 */
	@Test
	public void deleteAccountPasswordPolicy_notExist_fail_test() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setPasswordReusePrevention(24);
		client.updateAccountPasswordPolicy(updateRequest);
		// delete
		DeleteAccountPasswordPolicyRequest deleteRequest = new DeleteAccountPasswordPolicyRequest();
		client.deleteAccountPasswordPolicy(deleteRequest);
		try {
			client.deleteAccountPasswordPolicy(deleteRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The Password Policy with domain name 34e5k5ig79cjf cannot be found.", e.getMessage());
		}
	}

	/**
	 * 账号2执行删除账号1的密码策略，报404
	 */
	@Test
	public void deleteAccountPasswordPolicy_notExist_fail_test2() {
		// update
		UpdateAccountPasswordPolicyRequest updateRequest = new UpdateAccountPasswordPolicyRequest();
		updateRequest.setPasswordReusePrevention(24);
		client.updateAccountPasswordPolicy(updateRequest);
		// delete
		DeleteAccountPasswordPolicyRequest deleteRequest = new DeleteAccountPasswordPolicyRequest();
		try {
			client2.deleteAccountPasswordPolicy(deleteRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("The Password Policy with domain name 2khdzd8yb0pkw cannot be found.", e.getMessage());
		}
		client.deleteAccountPasswordPolicy(deleteRequest);
	}

	@Test
	public void group_ok_test() {
		// createGroup
		String groupName = "Group01";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		String groupId = group.getGroupId();
		String groupArn = group.getArn();
		Date createDate = group.getCreateDate();
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult userResult = client.createUser(cu);
		assertEquals(userName, userResult.getUser().getUserName());
		String userArn = userResult.getUser().getArn();
		String userId = userResult.getUser().getUserId();
		// 将用户添加到组
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, userName);
		client.addUserToGroup(addUserToGroupRequest);
		// getGroup
		GetGroupRequest getGroupRequest = new GetGroupRequest(groupName);
		GetGroupResult getResult = client.getGroup(getGroupRequest);
		List<User> users = getResult.getUsers();
		assertEquals(1, users.size());
		User user = users.get(0);
		assertEquals(userName, user.getUserName());
		assertEquals(userArn, user.getArn());
		assertEquals(userId, user.getUserId());
		System.out.println("------------getUser--------");
		System.out.println(user.getCreateDate());
		System.out.println(user.getPasswordLastUsed());
		System.out.println(user.getJoinDate());
		System.out.println("------getUser--------------");
		com.amazonaws.services.identitymanagement.model.Group getGroup = getResult.getGroup();
		assertEquals(groupName, getGroup.getGroupName());
		assertEquals(groupArn, getGroup.getArn());
		assertEquals(groupId, getGroup.getGroupId());
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 同一账户，创建重复group，大小写相同
	 */
	@Test
	public void createGroup_sameGroupName_fail_test() {
		// createGroup
		String groupName = "Group01";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		try {
			client.createGroup(createGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("EntityAlreadyExists", e.getErrorCode());
			assertEquals("Group with name " + groupName + " already exists.", e.getMessage());
		}
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 同一账户，创建重复group，大小写相同
	 */
	@Test
	public void createGroup_sameGroupName_fail_test2() {
		// createGroup
		String groupName = "Group01";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		try {
			groupName = "grouP01";
			createGroupRequest.setGroupName(groupName);
			client.createGroup(createGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("EntityAlreadyExists", e.getErrorCode());
			assertEquals("Group with name " + groupName + " already exists.", e.getMessage());
		}
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 不同账户，创建groupName相同的组
	 */
	@Test
	public void createGroup_sameGroupName_twoAccount_ok_test() {
		// 账户1
		String groupName = "Group01";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// 账户2
		createResult = client2.createGroup(createGroupRequest);
		group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());

		// 删除账户1的group
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		// 删除账户2的group
		client2.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void createGroup_length0_fail_test() {
		String groupName = "";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		try {
			client.createGroup(createGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: The specified value for 'groupName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
					e.getMessage());
		}
	}

	@Test
	public void createGroup_length1_ok_test() {
		// createGroup
		String groupName = "0";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		assertEquals(groupName, createResult.getGroup().getGroupName());
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void createGroup_length128_ok_test() {
		// createGroup
		String groupName = "";
		for (int i = 1; i <= 128; i++) {
			groupName += 2;
		}
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		assertEquals(groupName, createResult.getGroup().getGroupName());
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void createGroup_length129_fail_test() {
		// createGroup
		String groupName = "";
		for (int i = 1; i <= 129; i++) {
			groupName += 2;
		}
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		try {
			client.createGroup(createGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals("1 validation error detected: Value '" + groupName
					+ "' at 'groupName' failed to satisfy constraint: Member must have length less than or equal to 128",
					e.getMessage());
		}
	}

	@Test
	public void createGroup_containsBlank_fail_test() {
		// createGroup
		String groupName = "aa bb";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		try {
			client.createGroup(createGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'groupName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
					e.getMessage());
		}
	}

	@Test
	public void createGroup_specialCharacter_fail_test() {
		// createGroup
		String groupName = "~!@#$%";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		try {
			client.createGroup(createGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: The specified value for 'groupName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
					e.getMessage());
		}
	}

	@Test
	public void createGroup_specialCharacter_ok_test() {
		// createGroup
		String groupName = "TEst++=,.@-001";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		assertEquals(groupName, createResult.getGroup().getGroupName());
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void createGroup_noGroupName_fail_test() {
		// createGroup
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		try {
			client.createGroup(createGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
	}

	/**
	 * 多次重复添加同一个用户到同一个组，不会报错
	 */
	@Test
	public void addUserToGroup_repeatedAdd_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult userResult = client.createUser(cu);
		assertEquals(userName, userResult.getUser().getUserName());
		String userArn = userResult.getUser().getArn();
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// 将用户添加到组
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, userName);
		client.addUserToGroup(addUserToGroupRequest);
		client.addUserToGroup(addUserToGroupRequest);
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 指定的group不存在
	 */
	@Test
	public void addUserToGroup_group_notExist_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult userResult = client.createUser(cu);
		assertEquals(userName, userResult.getUser().getUserName());
		String userArn = userResult.getUser().getArn();
		// 将用户添加到组
		String groupName = "testGroup";
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest();
		addUserToGroupRequest.setUserName(userName);
		addUserToGroupRequest.setGroupName(groupName);
		try {
			client.addUserToGroup(addUserToGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The group with name " + groupName + " cannot be found.", e.getMessage());
		}
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 指定的user不存在
	 */
	@Test
	public void addUserToGroup_user_notExist_fail_test() {
		String userName = "sdktestuser";
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// 将用户添加到组
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest();
		addUserToGroupRequest.setUserName(userName);
		addUserToGroupRequest.setGroupName(groupName);
		try {
			client.addUserToGroup(addUserToGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name " + userName + " cannot be found.", e.getMessage());
		}
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 缺少groupName参数
	 */
	@Test
	public void addUserToGroup_groupNameNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult userResult = client.createUser(cu);
		assertEquals(userName, userResult.getUser().getUserName());
		String userArn = userResult.getUser().getArn();
		// 将用户添加到组
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest();
		addUserToGroupRequest.setUserName(userName);
		try {
			client.addUserToGroup(addUserToGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 缺少userName
	 */
	@Test
	public void addUserToGroup_userNameNull_fail_test() {
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// 将用户添加到组
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest();
		addUserToGroupRequest.setGroupName(groupName);
		try {
			client.addUserToGroup(addUserToGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * group不包含用户
	 */
	@Test
	public void getGroup_noUser_ok_test() {
		// createGroup
		String groupName = "Group01";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		String groupId = group.getGroupId();
		String groupArn = group.getArn();
		Date createDate = group.getCreateDate();
		// getGroup
		GetGroupRequest getGroupRequest = new GetGroupRequest(groupName);
		GetGroupResult getResult = client.getGroup(getGroupRequest);
		assertFalse(getResult.getIsTruncated());
		List<User> users = getResult.getUsers();
		assertEquals(0, users.size());
		com.amazonaws.services.identitymanagement.model.Group getGroup = getResult.getGroup();
		assertEquals(groupName, getGroup.getGroupName());
		assertEquals(groupArn, getGroup.getArn());
		assertEquals(groupId, getGroup.getGroupId());
		System.out.println(getGroup.getCreateDate());
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 创建1个组，添加3个用户到组
	 * 
	 */
	@Test
	public void getGroup_users3_ok_test() {
		// createGroup
		String groupName = "testGroup1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		client.createGroup(createGroupRequest);
		// createUser
		CreateUserRequest cu = new CreateUserRequest("sdktestuser1");
		client.createUser(cu);
		cu.setUserName("sdktestuser2");
		client.createUser(cu);
		cu.setUserName("sdktestuser3");
		client.createUser(cu);
		// 将用户添加到组
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, "sdktestuser1");
		client.addUserToGroup(addUserToGroupRequest);
		addUserToGroupRequest.setUserName("sdktestuser2");
		client.addUserToGroup(addUserToGroupRequest);
		addUserToGroupRequest.setUserName("sdktestuser3");
		client.addUserToGroup(addUserToGroupRequest);
		// getGroup
		GetGroupRequest getGroupRequest = new GetGroupRequest(groupName);
		GetGroupResult getResult = client.getGroup(getGroupRequest);
		assertFalse(getResult.getIsTruncated());
		List<User> users = getResult.getUsers();
		assertFalse(getResult.getIsTruncated());
		assertEquals(3, users.size());
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName,
				"sdktestuser1");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest.setUserName("sdktestuser2");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest.setUserName("sdktestuser3");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest("sdktestuser1");
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser3");
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 给组添加3个用户，但是MaxItems设置为1
	 * 
	 */
	@Test
	public void getGroup_maxItems1_ok_test() {
		// createGroup
		String groupName = "testGroup1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		client.createGroup(createGroupRequest);
		// createUser
		CreateUserRequest cu = new CreateUserRequest("sdktestuser1");
		client.createUser(cu);
		cu.setUserName("sdktestuser2");
		client.createUser(cu);
		cu.setUserName("sdktestuser3");
		client.createUser(cu);
		// 将用户添加到组
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, "sdktestuser1");
		client.addUserToGroup(addUserToGroupRequest);
		addUserToGroupRequest.setUserName("sdktestuser2");
		client.addUserToGroup(addUserToGroupRequest);
		addUserToGroupRequest.setUserName("sdktestuser3");
		client.addUserToGroup(addUserToGroupRequest);
		// getGroup
		GetGroupRequest getGroupRequest = new GetGroupRequest(groupName);
		getGroupRequest.setMaxItems(1);
		GetGroupResult getResult = client.getGroup(getGroupRequest);
		assertTrue(getResult.getIsTruncated());
		List<User> users = getResult.getUsers();
		assertEquals(1, users.size());
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName,
				"sdktestuser1");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest.setUserName("sdktestuser2");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest.setUserName("sdktestuser3");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest("sdktestuser1");
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser3");
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 给组添加3个用户，但是MaxItems设置为5
	 * 
	 */
	@Test
	public void getGroup_maxItems5_ok_test() {
		// createGroup
		String groupName = "testGroup1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		client.createGroup(createGroupRequest);
		// createUser
		CreateUserRequest cu = new CreateUserRequest("sdktestuser1");
		client.createUser(cu);
		cu.setUserName("sdktestuser2");
		client.createUser(cu);
		cu.setUserName("sdktestuser3");
		client.createUser(cu);
		// 将用户添加到组
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, "sdktestuser1");
		client.addUserToGroup(addUserToGroupRequest);
		addUserToGroupRequest.setUserName("sdktestuser2");
		client.addUserToGroup(addUserToGroupRequest);
		addUserToGroupRequest.setUserName("sdktestuser3");
		client.addUserToGroup(addUserToGroupRequest);
		// getGroup
		GetGroupRequest getGroupRequest = new GetGroupRequest(groupName);
		getGroupRequest.setMaxItems(5);
		GetGroupResult getResult = client.getGroup(getGroupRequest);
		assertFalse(getResult.getIsTruncated());
		List<User> users = getResult.getUsers();
		assertEquals(3, users.size());
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName,
				"sdktestuser1");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest.setUserName("sdktestuser2");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest.setUserName("sdktestuser3");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest("sdktestuser1");
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser3");
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void getGroup_marker1_ok_test() {
		// createGroup
		String groupName = "testGroup1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		client.createGroup(createGroupRequest);
		// createUser
		CreateUserRequest cu = new CreateUserRequest("sdktestuser1");
		client.createUser(cu);
		cu.setUserName("sdktestuser2");
		client.createUser(cu);
		cu.setUserName("sdktestuser3");
		client.createUser(cu);
		// 将用户添加到组
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, "sdktestuser1");
		client.addUserToGroup(addUserToGroupRequest);
		addUserToGroupRequest.setUserName("sdktestuser2");
		client.addUserToGroup(addUserToGroupRequest);
		addUserToGroupRequest.setUserName("sdktestuser3");
		client.addUserToGroup(addUserToGroupRequest);
		// getGroup
		GetGroupRequest getGroupRequest = new GetGroupRequest(groupName);
		getGroupRequest.setMarker("kkk");
		GetGroupResult getResult = client.getGroup(getGroupRequest);
		assertFalse(getResult.getIsTruncated());
		List<User> users = getResult.getUsers();
		assertEquals(3, users.size());
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName,
				"sdktestuser1");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest.setUserName("sdktestuser2");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		removeUserFromGroupRequest.setUserName("sdktestuser3");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest("sdktestuser1");
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser3");
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * groupName参数为null
	 * 
	 */
	@Test
	public void getGroup_groupNameNull_fail_test() {
		// createGroup
		String groupName = "testGroup1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		client.createGroup(createGroupRequest);
		// createUser
		CreateUserRequest cu = new CreateUserRequest("sdktestuser1");
		client.createUser(cu);
		// 将用户添加到组
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, "sdktestuser1");
		client.addUserToGroup(addUserToGroupRequest);
		// getGroup
		GetGroupRequest getGroupRequest = new GetGroupRequest(null);
		try {
			client.getGroup(getGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName,
				"sdktestuser1");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest("sdktestuser1");
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * maxItems设置为0
	 */
	@Test
	public void getGroup_maxItems0_fail_test() {
		// createGroup
		String groupName = "testGroup1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		client.createGroup(createGroupRequest);
		// createUser
		CreateUserRequest cu = new CreateUserRequest("sdktestuser1");
		client.createUser(cu);
		// 将用户添加到组
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, "sdktestuser1");
		client.addUserToGroup(addUserToGroupRequest);
		// getGroup
		GetGroupRequest getGroupRequest = new GetGroupRequest(groupName);
		getGroupRequest.setMaxItems(0);
		try {
			client.getGroup(getGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",
					e.getMessage());
		}
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName,
				"sdktestuser1");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest("sdktestuser1");
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * maxItems设置为1001
	 */
	@Test
	public void getGroup_maxItems1001_fail_test() {
		// createGroup
		String groupName = "testGroup1";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		client.createGroup(createGroupRequest);
		// createUser
		CreateUserRequest cu = new CreateUserRequest("sdktestuser1");
		client.createUser(cu);
		// 将用户添加到组
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, "sdktestuser1");
		client.addUserToGroup(addUserToGroupRequest);
		// getGroup
		GetGroupRequest getGroupRequest = new GetGroupRequest(groupName);
		getGroupRequest.setMaxItems(1001);
		try {
			client.getGroup(getGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
					e.getMessage());
		}
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName,
				"sdktestuser1");
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest("sdktestuser1");
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 不指定groupName,将账户下所有的group都列出
	 */
	@Test
	public void listGroups_noGroupName_ok_test() {
		// createGroup 3个
		CreateGroupRequest createGroupRequest = new CreateGroupRequest("testGroup1");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup2");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup3");
		client.createGroup(createGroupRequest);
		// 将subUser1和subUser2添加到testGroup1
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest("testGroup1", subUser1);
		client.addUserToGroup(addUserToGroupRequest);
		// 分配策略到testGroup1
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName("testGroup1");
		attachGroupPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listGroups
		ListGroupsRequest listGroupsRequest = new ListGroupsRequest();
		ListGroupsResult listResult = client.listGroups(listGroupsRequest);
		List<GroupResult> groups = listResult.getGroups();
		assertEquals(3, groups.size());
		for (GroupResult group : groups) {
			System.out.println(group.getGroupName());
			System.out.println(group.getArn());
			System.out.println(group.getGroupId());
			System.out.println(group.getCreateDate());
			System.out.println(group.getPolicies());
			System.out.println(group.getUsers());
		}
		// 解除策略
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest("testGroup1",
				"arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// 将用户从组中移除
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest("testGroup1", subUser1);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest("testGroup1");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup3");
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 
	 * 指定groupName,只列出指定的group
	 * 
	 */
	@Test
	public void listGroups_hasGroupName_ok_test() {
		// createGroup 3个
		CreateGroupRequest createGroupRequest = new CreateGroupRequest("testGroup1");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup2");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup3");
		client.createGroup(createGroupRequest);
		// 将subUser1和subUser2添加到testGroup1
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest("testGroup1", subUser1);
		client.addUserToGroup(addUserToGroupRequest);
		// 分配策略到testGroup1
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName("testGroup1");
		attachGroupPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listGroups
		ListGroupsRequest listGroupsRequest = new ListGroupsRequest();
		listGroupsRequest.setGroupName("testGroup1");
		ListGroupsResult listResult = client.listGroups(listGroupsRequest);
		List<GroupResult> groups = listResult.getGroups();
		assertEquals(1, groups.size());
		for (GroupResult group : groups) {
			System.out.println(group.getGroupName());
			System.out.println(group.getArn());
			System.out.println(group.getGroupId());
			System.out.println(group.getCreateDate());
			System.out.println(group.getPolicies());
			System.out.println(group.getUsers());
		}
		// 解除策略
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest("testGroup1",
				"arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// 将用户从组中移除
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest("testGroup1", subUser1);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest("testGroup1");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup3");
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 指定groupName，但是不存在,不报错，只是返回空
	 */
	@Test
	public void listGroups_hasGroupName_null_ok_test() {
		// createGroup 3个
		CreateGroupRequest createGroupRequest = new CreateGroupRequest("testGroup1");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup2");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup3");
		client.createGroup(createGroupRequest);
		// 将subUser1和subUser2添加到testGroup1
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest("testGroup1", subUser1);
		client.addUserToGroup(addUserToGroupRequest);
		// 分配策略到testGroup1
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName("testGroup1");
		attachGroupPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listGroups
		ListGroupsRequest listGroupsRequest = new ListGroupsRequest();
		listGroupsRequest.setGroupName("noGroup");
		ListGroupsResult listResult = client.listGroups(listGroupsRequest);
		List<GroupResult> groups = listResult.getGroups();
		assertEquals(0, groups.size());
		// 解除策略
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest("testGroup1",
				"arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// 将用户从组中移除
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest("testGroup1", subUser1);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest("testGroup1");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup3");
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listGroups_maxItems1_ok_test() {
		// createGroup 3个
		CreateGroupRequest createGroupRequest = new CreateGroupRequest("testGroup1");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup2");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup3");
		client.createGroup(createGroupRequest);
		// 将subUser1和subUser2添加到testGroup1
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest("testGroup1", subUser1);
		client.addUserToGroup(addUserToGroupRequest);
		// 分配策略到testGroup1
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName("testGroup1");
		attachGroupPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listGroups
		ListGroupsRequest listGroupsRequest = new ListGroupsRequest();
		listGroupsRequest.setMaxItems(1);
		ListGroupsResult listResult = client.listGroups(listGroupsRequest);
		List<GroupResult> groups = listResult.getGroups();
		assertEquals(1, groups.size());
		assertTrue(listResult.getIsTruncated());
		for (GroupResult group : groups) {
			System.out.println(group.getGroupName());
			System.out.println(group.getArn());
			System.out.println(group.getGroupId());
			System.out.println(group.getCreateDate());
			System.out.println(group.getPolicies());
			System.out.println(group.getUsers());
		}
		// 解除策略
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest("testGroup1",
				"arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// 将用户从组中移除
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest("testGroup1", subUser1);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest("testGroup1");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup3");
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listGroups_maxItems1000_ok_test() {
		// createGroup 3个
		CreateGroupRequest createGroupRequest = new CreateGroupRequest("testGroup1");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup2");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup3");
		client.createGroup(createGroupRequest);
		// 将subUser1和subUser2添加到testGroup1
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest("testGroup1", subUser1);
		client.addUserToGroup(addUserToGroupRequest);
		// 分配策略到testGroup1
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName("testGroup1");
		attachGroupPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listGroups
		ListGroupsRequest listGroupsRequest = new ListGroupsRequest();
		listGroupsRequest.setMaxItems(1000);
		ListGroupsResult listResult = client.listGroups(listGroupsRequest);
		List<GroupResult> groups = listResult.getGroups();
		assertEquals(3, groups.size());
		for (GroupResult group : groups) {
			System.out.println(group.getGroupName());
			System.out.println(group.getArn());
			System.out.println(group.getGroupId());
			System.out.println(group.getCreateDate());
			System.out.println(group.getPolicies());
			System.out.println(group.getUsers());
		}
		// 解除策略
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest("testGroup1",
				"arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// 将用户从组中移除
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest("testGroup1", subUser1);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest("testGroup1");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup3");
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listGroups_maxItems0_fail_test() {
		// createGroup 3个
		CreateGroupRequest createGroupRequest = new CreateGroupRequest("testGroup1");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup2");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup3");
		client.createGroup(createGroupRequest);
		// 将subUser1和subUser2添加到testGroup1
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest("testGroup1", subUser1);
		client.addUserToGroup(addUserToGroupRequest);
		// 分配策略到testGroup1
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName("testGroup1");
		attachGroupPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listGroups
		ListGroupsRequest listGroupsRequest = new ListGroupsRequest();
		listGroupsRequest.setMaxItems(0);
		try {
			client.listGroups(listGroupsRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",
					e.getMessage());
		}
		// 解除策略
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest("testGroup1",
				"arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// 将用户从组中移除
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest("testGroup1", subUser1);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest("testGroup1");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup3");
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listGroups_maxItems1001_fail_test() {
		// createGroup 3个
		CreateGroupRequest createGroupRequest = new CreateGroupRequest("testGroup1");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup2");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup3");
		client.createGroup(createGroupRequest);
		// 将subUser1和subUser2添加到testGroup1
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest("testGroup1", subUser1);
		client.addUserToGroup(addUserToGroupRequest);
		// 分配策略到testGroup1
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName("testGroup1");
		attachGroupPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listGroups
		ListGroupsRequest listGroupsRequest = new ListGroupsRequest();
		listGroupsRequest.setMaxItems(1001);
		try {
			client.listGroups(listGroupsRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
					e.getMessage());
		}
		// 解除策略
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest("testGroup1",
				"arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// 将用户从组中移除
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest("testGroup1", subUser1);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest("testGroup1");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup3");
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 创建4个组，maxItems设置为2 返回的marker是组2
	 * 
	 */
	@Test
	public void listGroups_marker_ok_test() {
		// createGroup 4个
		CreateGroupRequest createGroupRequest = new CreateGroupRequest("testGroup1");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup2");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup3");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup4");
		client.createGroup(createGroupRequest);
		// 将subUser1和subUser2添加到testGroup1
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest("testGroup1", subUser1);
		client.addUserToGroup(addUserToGroupRequest);
		// 分配策略到testGroup1
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName("testGroup1");
		attachGroupPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listGroups
		ListGroupsRequest listGroupsRequest = new ListGroupsRequest();
		listGroupsRequest.setMaxItems(2);
		ListGroupsResult listResult = client.listGroups(listGroupsRequest);
		List<GroupResult> groups = listResult.getGroups();
		assertEquals(2, groups.size());
		assertTrue(listResult.getIsTruncated());
		System.out.println(listResult.getMarker());
		assertEquals("34e5k5ig79cjf|testgroup2", listResult.getMarker());
		for (GroupResult group : groups) {
			System.out.println(group.getGroupName());
			System.out.println(group.getArn());
			System.out.println(group.getGroupId());
			System.out.println(group.getCreateDate());
			System.out.println(group.getPolicies());
			System.out.println(group.getUsers());
		}
		// 解除策略
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest("testGroup1",
				"arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// 将用户从组中移除
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest("testGroup1", subUser1);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest("testGroup1");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup3");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup4");
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 创建4个组，maxItems设置为1，marker设置为34e5k5ig79cjf|testgroup2 返回的marker是组3
	 * 
	 */
	@Test
	public void listGroups_marker_ok_test2() {
		// createGroup 4个
		CreateGroupRequest createGroupRequest = new CreateGroupRequest("testGroup1");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup2");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup3");
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup4");
		client.createGroup(createGroupRequest);
		// 将subUser1和subUser2添加到testGroup1
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest("testGroup1", subUser1);
		client.addUserToGroup(addUserToGroupRequest);
		// 分配策略到testGroup1
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName("testGroup1");
		attachGroupPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listGroups
		ListGroupsRequest listGroupsRequest = new ListGroupsRequest();
		listGroupsRequest.setMaxItems(1);
		listGroupsRequest.setMarker("34e5k5ig79cjf|testgroup2");
		ListGroupsResult listResult = client.listGroups(listGroupsRequest);
		List<GroupResult> groups = listResult.getGroups();
		assertEquals(1, groups.size());
		assertTrue(listResult.getIsTruncated());
		System.out.println("marker====" + listResult.getMarker());
		assertEquals("34e5k5ig79cjf|testgroup3", listResult.getMarker());
		for (GroupResult group : groups) {
			System.out.println(group.getGroupName());
			System.out.println(group.getArn());
			System.out.println(group.getGroupId());
			System.out.println(group.getCreateDate());
			System.out.println(group.getPolicies());
			System.out.println(group.getUsers());
		}
		// 解除策略
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest("testGroup1",
				"arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// 将用户从组中移除
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest("testGroup1", subUser1);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest("testGroup1");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup3");
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup4");
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 用户存在，但是不在组中，不报错，仍返回200
	 */
	@Test
	public void removeUserFromGroup_notInGroup_ok_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult userResult = client.createUser(cu);
		assertEquals(userName, userResult.getUser().getUserName());
		String userArn = userResult.getUser().getArn();
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 用户不存在
	 */
	@Test
	public void removeUserFromGroup_user_notExist_fail_test() {
		String userName = "sdktestuser";
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		try {
			client.removeUserFromGroup(removeUserFromGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The user with name " + userName + " cannot be found.", e.getMessage());

		}
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 组不存在
	 */
	@Test
	public void removeUserFromGroup_group_notExist_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult userResult = client.createUser(cu);
		assertEquals(userName, userResult.getUser().getUserName());
		String groupName = "testGroup";
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		try {
			client.removeUserFromGroup(removeUserFromGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The group with name " + groupName + " cannot be found.", e.getMessage());
		}
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * user为null
	 */
	@Test
	public void removeUserFromGroup_userNameNull_fail_test() {
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, null);
		try {
			client.removeUserFromGroup(removeUserFromGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());

		}
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * groupName参数为null
	 */
	@Test
	public void removeUserFromGroup_groupNameNull_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult userResult = client.createUser(cu);
		assertEquals(userName, userResult.getUser().getUserName());
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest();
		removeUserFromGroupRequest.setUserName(userName);
		try {
			client.removeUserFromGroup(removeUserFromGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 组包含用户，删除组失败
	 */
	@Test
	public void deleteGroup_hasUser_fail_test() {
		// 创建用户
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest();
		cu.setUserName(userName);
		CreateUserResult userResult = client.createUser(cu);
		assertEquals(userName, userResult.getUser().getUserName());
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// 用户添加到组
		AddUserToGroupRequest addUserToGroupRequest = new AddUserToGroupRequest(groupName, userName);
		client.addUserToGroup(addUserToGroupRequest);
		// 删除组失败
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		try {
			client.deleteGroup(deleteGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("DeleteConflict", e.getErrorCode());
			assertEquals("Cannot delete entity, must remove users from group first.", e.getMessage());
		}
		// 将用户移出组
		RemoveUserFromGroupRequest removeUserFromGroupRequest = new RemoveUserFromGroupRequest(groupName, userName);
		client.removeUserFromGroup(removeUserFromGroupRequest);
		// deleteGroup
		client.deleteGroup(deleteGroupRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);

	}

	/**
	 * 组包含策略，删除组失败
	 */
	@Test
	public void deleteGroup_hasPolicy_fail_test() {
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// 为组附加策略
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// 删除组失败
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		try {
			client.deleteGroup(deleteGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("DeleteConflict", e.getErrorCode());
			assertEquals("Cannot delete entity, must detach all policies first.", e.getMessage());
		}
		// 解除策略
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deleteGroup
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 指定的group不存在
	 */
	@Test
	public void deleteGroup_noGroup_fail_test() {
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// 删除组失败
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest("noGroupXX");
		try {
			client.deleteGroup(deleteGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			assertEquals("The group with name noGroupXX cannot be found.", e.getMessage());
		}
		// deleteGroup
		deleteGroupRequest.setGroupName(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * groupName参数为null
	 */
	@Test
	public void deleteGroup_groupNameNull_fail_test() {
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// 删除组失败
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest();
		try {
			client.deleteGroup(deleteGroupRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// deleteGroup
		deleteGroupRequest.setGroupName(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	// --------------------------策略篇------------------------

	@Test
	public void policy_ok_test() {
		// createPolicy
		String policyName = "testPolicy";
		String desc = "test desc";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setDescription(desc);
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult createResult = client.createPolicy(createPolicyRequest);
		Policy policy = createResult.getPolicy();
		assertEquals(policyName, policy.getPolicyName());
		assertEquals(desc, policy.getDescription());
		assertTrue(policy.getIsAttachable());
		Date update = policy.getUpdateDate();
		String policyId = policy.getPolicyId();
		int attachmentCount = policy.getAttachmentCount();
		String policyArn = policy.getArn();
		Date createDate = policy.getCreateDate();
		// createGroup attachGroupPolicy
		String groupName = "Group01";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		client.createGroup(createGroupRequest);
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(policyArn);
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// createUser attachUserPolicy
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		// getPolicy
		GetPolicyRequest request = new GetPolicyRequest();
		request.setPolicyArn(policyArn);
		GetPolicyResult getResult = client.getPolicy(request);
		Policy getPolicy = getResult.getPolicy();
		assertEquals(policyName, getPolicy.getPolicyName());
		assertEquals(policyId, getPolicy.getPolicyId());
		assertTrue(getPolicy.getIsAttachable());
		assertEquals(desc, getPolicy.getDescription());
		assertEquals(policyArn, getPolicy.getArn());
		assertEquals(2, getPolicy.getAttachmentCount().intValue());
		assertEquals("Local", getPolicy.getScope());
		System.out.println("-------------getPolicy-------------");
		System.out.println(getPolicy.getAttachmentCount());
		System.out.println(getPolicy.getScope());
		System.out.println(getPolicy.getCreateDate());
		System.out.println(getPolicy.getUpdateDate());
		System.out.println(getPolicy.getDocument());
		System.out.println("-------------getPolicy--------------");
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest(userName, policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		// detachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest(groupName, policyArn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 可以创建同名的策略，新策略会覆盖之前的策略信息，更新策略时，policyName和Path必须和之前一致。 policyName不区分大小写
	 * 修改document、desc、policyName
	 */
	@Test
	public void createPolicy_twoSamePolicyName_ok_test() {
		// createPolicy
		String policyName = "testPolicy";
		String desc = "test desc";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setDescription(desc);
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult createResult = client.createPolicy(createPolicyRequest);
		String policyArn = createResult.getPolicy().getArn();
		assertEquals(policyName, createResult.getPolicy().getPolicyName());

		String policyName2 = "TestPolicy";
		String policyDocument2 = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:GetObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument2);
		createPolicyRequest.setDescription("desc test");
		createPolicyRequest.setPolicyName(policyName2);
		client.createPolicy(createPolicyRequest);

		// getPolicy
		GetPolicyRequest request = new GetPolicyRequest();
		request.setPolicyArn(policyArn);
		GetPolicyResult getResult = client.getPolicy(request);
		Policy getPolicy = getResult.getPolicy();
		assertEquals(policyDocument2, getPolicy.getDocument());
		assertEquals("desc test", getPolicy.getDescription());
		assertEquals(policyName2, getPolicy.getPolicyName());
		System.out.println(getPolicy.getPolicyName());

		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * PolicyName包含特殊符号
	 * 
	 */
	@Test
	public void createDeletePolicy_specialCharacter_ok_test() {
		// createPolicy
		String policyName = "TEstcreatePOlicy++=,.@-001";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult createResult = client.createPolicy(createPolicyRequest);
		assertEquals(policyName, createResult.getPolicy().getPolicyName());
		String policyArn = createResult.getPolicy().getArn();

		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);

	}

	@Test
	public void createDeletePolicy_validPolicyName128_ok_test() {
		// createPolicy
		String policyName = "";
		for (int i = 1; i <= 128; i++) {
			policyName += "a";
		}
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult createResult = client.createPolicy(createPolicyRequest);
		assertEquals(policyName, createResult.getPolicy().getPolicyName());
		String policyArn = createResult.getPolicy().getArn();
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
	}

	@Test
	public void createDeletePolicy_validPolicyName1_ok_test() {
		// createPolicy
		String policyName = "p";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult createResult = client.createPolicy(createPolicyRequest);
		assertEquals(policyName, createResult.getPolicy().getPolicyName());
		String policyArn = createResult.getPolicy().getArn();
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * 
	 * PolicyName参数为null
	 */
	@Test
	public void createDeletePolicy_policyNameNull_fail_test() {
		// createPolicy
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(null);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals(
					"1 validation error detected: Value null at 'policyName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
	}

	/**
	 * 
	 * PolicyName包含空格特殊字符
	 */
	@Test
	public void createDeletePolicy_invalidPolicyName_fail_test() {
		// createPolicy
		String policyName = "aa bb";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: The specified value for 'policyName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
					e.getMessage());
		}
	}

	/**
	 * 
	 * PolicyName长度超过限制，129
	 */
	@Test
	public void createDeletePolicy_invalidPolicyName129_fail_test() {
		// createPolicy
		String policyName = "";
		for (int i = 1; i <= 129; i++) {
			policyName += "a";
		}
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("1 validation error detected: Value '" + policyName
					+ "' at 'policyName' failed to satisfy constraint: Member must have length less than or equal to 128",
					e.getMessage());
		}
	}

	/**
	 * 必填项校验： policyDocument为空
	 */
	@Test
	public void createDeletePolicy_noPolicyDocument_fail_test() {
		// createPolicy
		String policyName = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'policyDocument' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
	}

	/**
	 * 创建策略时，policy不是json格式
	 */
	@Test
	public void createDeletePolicy_invalidDocumentJson_fail_test() {
		// createPolicy
		String policyName = "p";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "a";
		createPolicyRequest.setPolicyDocument(policyDocument);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("MalformedPolicyDocument", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Syntax errors in policy.", e.getMessage());
		}
	}

	/**
	 * 创建策略时，条件运算符或者条件键不正确
	 */
	@Test
	public void createDeletePolicy_invalidCondition_fail_test() {
		// createPolicy
		String policyName = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1571283086078\",\"Statement\":[{\"Sid\":\"1571283086078_1\",\"Effect\":\"Allow\",\"Action\":[\"oos:PutObject\",\"oos:GetObject\",\"oos:DeleteObject\"],\"Resource\":\"arn:ctyun:oos::3rmoqzn03g6ga:test01/*\",\"Condition\":{\"StringEqualsqq\":{\"ctyun:username\":\"test_2\"}}}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("MalformedPolicyDocument", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Invalid Condition type : StringEqualsqq.", e.getMessage());
		}
	}

	/**
	 * 创建策略时，Resouce和NotResource都有
	 */
	@Test
	public void createDeletePolicy_ResourceNotResource_fail_test() {
		// createPolicy
		String policyName = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1571283086078\",\"Statement\":[{\"Sid\":\"1571283086078_1\",\"Effect\":\"Allow\",\"Action\":[\"oos:PutObject\",\"oos:GetObject\",\"oos:DeleteObject\"],\"Resource\":\"arn:ctyun:oos::3rmoqzn03g6ga:test01/*\",\"NotResource\":\"arn:ctyun:oos::3rmoqzn03g6ga:test01/*\",\"Condition\":{\"StringEquals\":{\"ctyun:username\":\"test_2\"}}}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("MalformedPolicyDocument", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Statement/policy already has instance of Resource.", e.getMessage());
		}
	}

	/**
	 * 创建策略时，resource没有
	 */
	@Test
	public void createDeletePolicy_noResource_fail_test() {
		// createPolicy
		String policyName = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1571283086078\",\"Statement\":[{\"Sid\":\"1571283086078_1\",\"Effect\":\"Allow\",\"Action\":[\"oos:PutObject\",\"oos:GetObject\",\"oos:DeleteObject\"],\"Condition\":{\"StringEquals\":{\"ctyun:username\":\"test_2\"}}}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("MalformedPolicyDocument", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Missing required field Resource.", e.getMessage());
		}
	}

	/**
	 * 创建策略时，Action和NotAction都有时，报错
	 */
	@Test
	public void createDeletePolicy_ActionNotAction_fail_test() {
		// createPolicy
		String policyName = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1571283086078\",\"Statement\":[{\"Sid\":\"1571283086078_1\",\"Effect\":\"Allow\",\"NotAction\":[\"oos:PutObject\",\"oos:GetObject\",\"oos:DeleteObject\"],\"Action\":[\"oos:PutObject\",\"oos:GetObject\",\"oos:DeleteObject\"],\"Resource\":\"arn:ctyun:oos::3rmoqzn03g6ga:test01/*\",\"Condition\":{\"StringEquals\":{\"ctyun:username\":\"test_2\"}}}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("MalformedPolicyDocument", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Statement/policy already has instance of Action.", e.getMessage());
		}
	}

	/**
	 * 创建策略时，没有Action
	 */
	@Test
	public void createDeletePolicy_noAction_fail_test() {
		// createPolicy
		String policyName = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1571283086078\",\"Statement\":[{\"Sid\":\"1571283086078_1\",\"Effect\":\"Allow\",\"Resource\":\"arn:ctyun:oos::3rmoqzn03g6ga:test01/*\",\"Condition\":{\"StringEquals\":{\"ctyun:username\":\"test_2\"}}}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("MalformedPolicyDocument", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Missing required field Action.", e.getMessage());
		}
	}

	/**
	 * 创建策略时，Effect不对
	 */
	@Test
	public void createDeletePolicy_invalidEffect_fail_test() {
		// createPolicy
		String policyName = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1571283086078\",\"Statement\":[{\"Sid\":\"1571283086078_1\",\"Effect\":\"Allow1\",\"Action\":[\"oos:PutObject\",\"oos:GetObject\",\"oos:DeleteObject\"],\"Resource\":\"arn:ctyun:oos::3rmoqzn03g6ga:test01/*\",\"Condition\":{\"StringEquals\":{\"ctyun:username\":\"test_2\"}}}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("MalformedPolicyDocument", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Invalid effect: Allow1.", e.getMessage());
		}
	}

	/**
	 * 创建策略时，没有Effect
	 */
	@Test
	public void createDeletePolicy_noEffect_fail_test() {
		// createPolicy
		String policyName = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1571283086078\",\"Statement\":[{\"Sid\":\"1571283086078_1\",\"Action\":[\"oos:PutObject\",\"oos:GetObject\",\"oos:DeleteObject\"],\"Resource\":\"arn:ctyun:oos::3rmoqzn03g6ga:test01/*\",\"Condition\":{\"StringEquals\":{\"ctyun:username\":\"test_2\"}}}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("MalformedPolicyDocument", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Missing required field Effect.", e.getMessage());
		}
	}

	/**
	 * 创建策略时，没有Version
	 */
	@Test
	public void createDeletePolicy_noVersion_fail_test() {
		// createPolicy
		String policyName = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Id\":\"1571283086078\",\"Statement\":[{\"Sid\":\"1571283086078_1\",\"Effect\":\"Allow\",\"Action\":[\"oos:PutObject\",\"oos:GetObject\",\"oos:DeleteObject\"],\"Resource\":\"arn:ctyun:oos::3rmoqzn03g6ga:test01/*\",\"Condition\":{\"StringEquals\":{\"ctyun:username\":\"test_2\"}}}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("MalformedPolicyDocument", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("The policy must contain a valid version string.", e.getMessage());
		}
	}

	/**
	 * 创建策略时，非法Version
	 */
	@Test
	public void createDeletePolicy_invalidVersion_fail_test() {
		// createPolicy
		String policyName = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10\",\"Id\":\"1571283086078\",\"Statement\":[{\"Sid\":\"1571283086078_1\",\"Effect\":\"Allow\",\"Action\":[\"oos:PutObject\",\"oos:GetObject\",\"oos:DeleteObject\"],\"Resource\":\"arn:ctyun:oos::3rmoqzn03g6ga:test01/*\",\"Condition\":{\"StringEquals\":{\"ctyun:username\":\"test_2\"}}}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("MalformedPolicyDocument", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("The policy must contain a valid version string.", e.getMessage());
		}
	}

	/**
	 * root1@test.com账户setup的时候已创建1个策略。
	 *
	 */
	@Test
	public void createDeletePolicy_limitExceeded_fail_test() {
		String[] arns = new String[149];
		// createPolicy
		for (int i = 0; i < 149; i++) {
			String name = "" + i;
			CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
			createPolicyRequest.setPolicyName(name);
			String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
			createPolicyRequest.setPolicyDocument(policyDocument);
			CreatePolicyResult result = client.createPolicy(createPolicyRequest);
			String arn = result.getPolicy().getArn();
			arns[i] = arn;
		}
		String policyName = "testPolicy150"; // 账户中第151个策略
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(policyName);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		try {
			client.createPolicy(createPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(409, e.getStatusCode());
			assertEquals("LimitExceeded", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Cannot exceed quota for PoliciesPerAccount: 150.", e.getMessage());
		}

		// 删除创建的149个policy
		for (int i = 0; i < 149; i++) {
			DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
			deletePolicyRequest.setPolicyArn(arns[i]);
			client.deletePolicy(deletePolicyRequest);
		}
	}

	/**
	 * 必填校验：arn为空
	 */
	@Test
	public void attatchGroupPolicy_nullArn_fail_test() {
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(null);
		try {
			client.attachGroupPolicy(attachGroupPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'policyArn' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * arn中的账户id和不是请求者的账户id Policy is outside your own account.
	 */
	@Test
	public void attatchGroupPolicy_accessDeniedArn_fail_test() {
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		try {
			client2.attachGroupPolicy(attachGroupPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(403, e.getStatusCode());
			assertEquals("AccessDenied", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Policy is outside your own account.", e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 策略的Arn不合法
	 * 
	 */
	@Test
	public void attatchGroupPolicy_invalidInputArn_fail_test() {
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf::/*");
		try {
			client.attachGroupPolicy(attachGroupPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("InvalidInput", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("ARN arn:ctyun:iam::34e5k5ig79cjf::/* is not valid.", e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 组不存在
	 * 
	 */
	@Test
	public void attatchGroupPolicy_noGroup_fail_test() {
		String groupName = "testGroup";
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		try {
			client.attachGroupPolicy(attachGroupPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("The group with name testGroup cannot be found.", e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * 必填校验：groupName
	 * 
	 */
	@Test
	public void attatchGroupPolicy_nullGroupName_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(null);
		attachGroupPolicyRequest.setPolicyArn(arn);
		try {
			client.attachGroupPolicy(attachGroupPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
	}

	@Test
	public void attatchGroupPolicy_groupName_length0_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName("");
		attachGroupPolicyRequest.setPolicyArn(arn);
		try {
			client.attachGroupPolicy(attachGroupPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: The specified value for 'groupName' is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
					e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
	}

	@Test
	public void attatchGroupPolicy_groupName_length129_fail_test() {
		String groupName = "";
		for (int i = 1; i <= 129; i++) {
			groupName += "a";
		}
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		try {
			client.attachGroupPolicy(attachGroupPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			assertEquals("1 validation error detected: Value '" + groupName
					+ "' at 'groupName' failed to satisfy constraint: Member must have length less than or equal to 128",
					e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * 
	 * arn为空
	 */
	@Test
	public void attachUserPolicy_nullArn_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser attachUserPolicy
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(null);
		attachUserPolicyRequest.setUserName(userName);
		try {
			client.attachUserPolicy(attachUserPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'policyArn' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void attatchUserPolicy_accessDeniedArn_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser attachUserPolicy
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		try {
			client2.attachUserPolicy(attachUserPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(403, e.getStatusCode());
			assertEquals("AccessDenied", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Policy is outside your own account.", e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void attatchUserPolicy_invalidInputArn_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser attachUserPolicy
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf::/*");
		attachUserPolicyRequest.setUserName(userName);
		try {
			client.attachUserPolicy(attachUserPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("InvalidInput", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("ARN arn:ctyun:iam::34e5k5ig79cjf::/* is not valid.", e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 
	 * user不存在
	 */
	@Test
	public void attatchUserPolicy_user_notExist_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// attachUserPolicy
		String userName = "noUsermm";
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		try {
			client.attachUserPolicy(attachUserPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("The user with name noUsermm cannot be found.", e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
	}

	@Test
	public void attatchUserPolicy_nullUser_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(null);
		try {
			client.attachUserPolicy(attachUserPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
	}

	@Test
	public void detachGroupPolicy_nullArn_fail_test() {
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// detachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(null);
		try {
			client.detachGroupPolicy(detachGroupPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'policyArn' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		detachGroupPolicyRequest.setPolicyArn(arn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);

	}

	@Test
	public void detachGroupPolicy_accessDeniedArn_fail_test() {
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// detachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(arn);
		try {
			client2.detachGroupPolicy(detachGroupPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(403, e.getStatusCode());
			assertEquals("AccessDenied", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Policy is outside your own account.", e.getMessage());
		}
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void detachGroupPolicy_invalidInputArn_fail_test() {
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// detachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf::/*");
		try {
			client.detachGroupPolicy(detachGroupPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("InvalidInput", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("ARN arn:ctyun:iam::34e5k5ig79cjf::/* is not valid.", e.getMessage());
		}
		detachGroupPolicyRequest.setPolicyArn(arn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 
	 * 指定的group不存在
	 */
	@Test
	public void detachGroupPolicy_noGroup_fail_test() {
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// detachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName("noXx");
		detachGroupPolicyRequest.setPolicyArn(arn);
		try {
			client.detachGroupPolicy(detachGroupPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("The group with name noXx cannot be found.", e.getMessage());
		}
		detachGroupPolicyRequest.setGroupName(groupName);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void detachGroupPolicy_nullGroup_fail_test() {
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// detachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(null);
		detachGroupPolicyRequest.setPolicyArn(arn);
		try {
			client.detachGroupPolicy(detachGroupPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		detachGroupPolicyRequest.setGroupName(groupName);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * group和policy都存在，但是没有绑定。 不报错
	 * 
	 */
	@Test
	public void detachGroupPolicy_noAttatch_ok_test() {
		// 创建组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();
		// detachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(arn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void detachUserPolicy_nullArn_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser attachUserPolicy
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(null);
		try {
			client.detachUserPolicy(detachUserPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'policyArn' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);

	}

	@Test
	public void detachUserPolicy_accessDeniedArn_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser attachUserPolicy
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		System.out.println("---" + policyArn);
		try {
			client2.detachUserPolicy(detachUserPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(403, e.getStatusCode());
			assertEquals("AccessDenied", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Policy is outside your own account.", e.getMessage());
		}
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	@Test
	public void detachUserPolicy_invalidInputArn_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser attachUserPolicy
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf::/*");
		try {
			client.detachUserPolicy(detachUserPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("InvalidInput", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("ARN arn:ctyun:iam::34e5k5ig79cjf::/* is not valid.", e.getMessage());
		}
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);

	}

	/**
	 * 
	 * 指定的user不存在
	 */
	@Test
	public void detachUserPolicy_noUser_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser attachUserPolicy
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName("xxxx");
		detachUserPolicyRequest.setPolicyArn(policyArn);
		try {
			client.detachUserPolicy(detachUserPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("The user with name xxxx cannot be found.", e.getMessage());
		}
		detachUserPolicyRequest.setUserName(userName);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);

	}

	@Test
	public void detachUserPolicy_nullUser_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser attachUserPolicy
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(null);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		try {
			client.detachUserPolicy(detachUserPolicyRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		detachUserPolicyRequest.setUserName(userName);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);

	}

	/**
	 * user和policy都存在，但是没有相互绑定。不报错。
	 * 
	 */
	@Test
	public void detachUserPolicy_noAttatch_ok_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 策略存在，但未添加到组、用户中。
	 * 
	 */
	@Test
	public void getPolicy_noUserNoGroup_ok_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("测试");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		Policy policy = result.getPolicy();
		String policyArn = policy.getArn();
		String policyId = policy.getPolicyId();
		String desc = policy.getDescription();
		// getPolicy
		GetPolicyRequest request = new GetPolicyRequest();
		request.setPolicyArn(policyArn);
		GetPolicyResult getResult = client.getPolicy(request);
		Policy getPolicy = getResult.getPolicy();
		assertEquals(name, getPolicy.getPolicyName());
		assertEquals(policyId, getPolicy.getPolicyId());
		assertTrue(getPolicy.getIsAttachable());
		assertEquals(desc, getPolicy.getDescription());
		assertEquals(policyArn, getPolicy.getArn());
		assertEquals(0, getPolicy.getAttachmentCount().intValue());
		assertEquals("Local", getPolicy.getScope());
		System.out.println("-------------getPolicy-------------");
		System.out.println(getPolicy.getAttachmentCount());
		System.out.println(getPolicy.getScope());
		System.out.println(getPolicy.getCreateDate());
		System.out.println(getPolicy.getUpdateDate());
		System.out.println(getPolicy.getDocument());
		System.out.println("-------------getPolicy--------------");
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * 策略存在，绑定两个组，未绑定用户
	 * 
	 */
	@Test
	public void getPolicy_attachGroup_ok_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("测试");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		Policy policy = result.getPolicy();
		String policyArn = policy.getArn();
		String policyId = policy.getPolicyId();
		String desc = policy.getDescription();
		// 创建2个组
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		client.createGroup(createGroupRequest);
		createGroupRequest.setGroupName("testGroup2");
		client.createGroup(createGroupRequest);
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(policyArn);
		client.attachGroupPolicy(attachGroupPolicyRequest);
		attachGroupPolicyRequest.setGroupName("testGroup2");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// getPolicy
		GetPolicyRequest request = new GetPolicyRequest();
		request.setPolicyArn(policyArn);
		GetPolicyResult getResult = client.getPolicy(request);
		Policy getPolicy = getResult.getPolicy();
		assertEquals(name, getPolicy.getPolicyName());
		assertEquals(policyId, getPolicy.getPolicyId());
		assertTrue(getPolicy.getIsAttachable());
		assertEquals(desc, getPolicy.getDescription());
		assertEquals(policyArn, getPolicy.getArn());
		assertEquals(2, getPolicy.getAttachmentCount().intValue());
		assertEquals("Local", getPolicy.getScope());
		System.out.println("-------------getPolicy-------------");
		System.out.println(getPolicy.getAttachmentCount());
		System.out.println(getPolicy.getScope());
		System.out.println(getPolicy.getCreateDate());
		System.out.println(getPolicy.getUpdateDate());
		System.out.println(getPolicy.getDocument());
		System.out.println("-------------getPolicy--------------");
		// detachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(policyArn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setGroupName("testGroup2");
		client.detachGroupPolicy(detachGroupPolicyRequest);

		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * policy存在，只绑定user
	 * 
	 */
	@Test
	public void getPolicy_attachUser_ok_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("测试");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		Policy policy = result.getPolicy();
		String policyArn = policy.getArn();
		String policyId = policy.getPolicyId();
		String desc = policy.getDescription();
		// 创建2个user，并绑定策略
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		cu.setUserName("sdktestuser2");
		client.createUser(cu);
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setUserName("sdktestuser2");
		client.attachUserPolicy(attachUserPolicyRequest);
		// getPolicy
		GetPolicyRequest request = new GetPolicyRequest();
		request.setPolicyArn(policyArn);
		GetPolicyResult getResult = client.getPolicy(request);
		Policy getPolicy = getResult.getPolicy();
		assertEquals(name, getPolicy.getPolicyName());
		assertEquals(policyId, getPolicy.getPolicyId());
		assertTrue(getPolicy.getIsAttachable());
		assertEquals(desc, getPolicy.getDescription());
		assertEquals(policyArn, getPolicy.getArn());
		assertEquals(2, getPolicy.getAttachmentCount().intValue());
		assertEquals("Local", getPolicy.getScope());
		System.out.println("-------------getPolicy-------------");
		System.out.println(getPolicy.getAttachmentCount());
		System.out.println(getPolicy.getScope());
		System.out.println(getPolicy.getCreateDate());
		System.out.println(getPolicy.getUpdateDate());
		System.out.println(getPolicy.getDocument());
		System.out.println("-------------getPolicy--------------");
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setUserName("sdktestuser2");
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteuser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * 
	 * policy不存在
	 */
	@Test
	public void getPolicy_noPolicy_fail_test() {
		String policyName = "createPolicyfortestPolicynotexist";
		String policyArn = "arn:ctyun:iam::34e5k5ig79cjf:policy/" + policyName;
		GetPolicyRequest request = new GetPolicyRequest();
		request.setPolicyArn(policyArn);
		try {
			client.getPolicy(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"Policy arn:ctyun:iam::34e5k5ig79cjf:policy/createPolicyfortestPolicynotexist does not exist or is not attachable.",
					e.getMessage());
		}
	}

	@Test
	public void getPolicy_nullArn_fail_test() {
		GetPolicyRequest request = new GetPolicyRequest();
		request.setPolicyArn(null);
		try {
			client.getPolicy(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'policyArn' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
	}

	@Test
	public void getPolicy_accessDeniedArn_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("测试");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::2khdzd8yb0pkw:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		// getPolicy
		GetPolicyRequest request = new GetPolicyRequest();
		System.out.println(result.getPolicy().getArn());
		request.setPolicyArn(result.getPolicy().getArn());
		try {
			client2.getPolicy(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(403, e.getStatusCode());
			assertEquals("AccessDenied", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"User: arn:ctyun:iam::2khdzd8yb0pkw:user/user2@oos.com is not authorized to perform: iam:GetPolicy on resource: arn:ctyun:iam::34e5k5ig79cjf:policy/testPolicy.",
					e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(result.getPolicy().getArn());
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * group绑定一个策略
	 */
	@Test
	public void listAttachedGroupPolicies_ok_test() {
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("desc test");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listAttachedGroupPolicies
		ListAttachedGroupPoliciesRequest request = new ListAttachedGroupPoliciesRequest();
		request.setGroupName(groupName);
		ListAttachedGroupPoliciesResult listResult = client.listAttachedGroupPolicies(request);
		List<AttachedPolicy> policies = listResult.getAttachedPolicies();
		AttachedPolicy policy = policies.get(0);
		assertEquals(1, policies.size());
		assertEquals(name, policy.getPolicyName());
		assertEquals("Local", policy.getScope());
		assertEquals("desc test", policy.getDescription());
		assertEquals(arn, policy.getPolicyArn());
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(arn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * group绑定2个策略
	 * 
	 */
	@Test
	public void listAttachedGroupPolicies_ok_test2() {
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("desc test");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();

		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("desc test2");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String arn2 = result2.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setPolicyArn(arn2);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		// listAttachedGroupPolicies
		ListAttachedGroupPoliciesRequest request = new ListAttachedGroupPoliciesRequest();
		request.setGroupName(groupName);
		ListAttachedGroupPoliciesResult listResult = client.listAttachedGroupPolicies(request);
		List<AttachedPolicy> policies = listResult.getAttachedPolicies();
		AttachedPolicy policy = policies.get(0);
		assertEquals(2, policies.size());
		System.out.println("---------------policy info-------------");
		for (AttachedPolicy policy2 : policies) {
			System.out.println(policy2.getPolicyName());
			System.out.println(policy2.getPolicyArn());
			System.out.println(policy2.getDescription());
			System.out.println(policy2.getScope());
		}
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(arn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setPolicyArn(arn2);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(arn2);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * group没有绑定策略
	 * 
	 */
	@Test
	public void listAttachedGroupPolicies_ok_test3() {
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());

		// listAttachedGroupPolicies
		ListAttachedGroupPoliciesRequest request = new ListAttachedGroupPoliciesRequest();
		request.setGroupName(groupName);
		ListAttachedGroupPoliciesResult listResult = client.listAttachedGroupPolicies(request);
		List<AttachedPolicy> policies = listResult.getAttachedPolicies();
		assertEquals(0, policies.size());
		assertFalse(listResult.getIsTruncated());

		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 空值校验：groupName为空
	 * 
	 */
	@Test
	public void listAttachedGroupPolicies_nullGroupName_fail_test() {
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("desc test");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();

		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("desc test2");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String arn2 = result2.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setPolicyArn(arn2);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		// listAttachedGroupPolicies
		ListAttachedGroupPoliciesRequest request = new ListAttachedGroupPoliciesRequest();
		request.setGroupName(null);
		try {
			client.listAttachedGroupPolicies(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'groupName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(arn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setPolicyArn(arn2);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(arn2);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 指定的group不存在
	 * 
	 */
	@Test
	public void listAttachedGroupPolicies_group_notExist_fail_test() {
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("desc test");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();

		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("desc test2");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String arn2 = result2.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setPolicyArn(arn2);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		// listAttachedGroupPolicies
		ListAttachedGroupPoliciesRequest request = new ListAttachedGroupPoliciesRequest();
		request.setGroupName("noGroupXX");
		try {
			client.listAttachedGroupPolicies(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("The group with name noGroupXX cannot be found.", e.getMessage());
		}
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(arn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setPolicyArn(arn2);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(arn2);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listAttachedGroupPolicies_maxItems0_fail_test() {
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("desc test");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();

		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("desc test2");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String arn2 = result2.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setPolicyArn(arn2);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		// listAttachedGroupPolicies
		ListAttachedGroupPoliciesRequest request = new ListAttachedGroupPoliciesRequest();
		request.setGroupName(groupName);
		request.setMaxItems(0);
		try {
			client.listAttachedGroupPolicies(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",
					e.getMessage());
		}
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(arn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setPolicyArn(arn2);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(arn2);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listAttachedGroupPolicies_markerLength0_fail_test() {
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("desc test");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();

		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("desc test2");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String arn2 = result2.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setPolicyArn(arn2);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		// listAttachedGroupPolicies
		ListAttachedGroupPoliciesRequest request = new ListAttachedGroupPoliciesRequest();
		request.setGroupName(groupName);
		request.setMarker("");
		try {
			client.listAttachedGroupPolicies(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: The specified value for 'marker' is invalid. It must contain only printable ASCII characters",
					e.getMessage());
		}
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(arn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setPolicyArn(arn2);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(arn2);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * group绑定2个策略 marker设置为testPolicy list数据为testPolicy2
	 * 
	 */
	@Test
	public void listAttachedGroupPolicies_marker_ok_test() {
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("desc test");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();

		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("desc test2");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String arn2 = result2.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setPolicyArn(arn2);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		// listAttachedGroupPolicies
		ListAttachedGroupPoliciesRequest request = new ListAttachedGroupPoliciesRequest();
		request.setGroupName(groupName);
		request.setMarker("policy|34e5k5ig79cjf|testgroup|Local|testpolicy");
		ListAttachedGroupPoliciesResult listResult = client.listAttachedGroupPolicies(request);
		List<AttachedPolicy> policies = listResult.getAttachedPolicies();
		assertEquals(1, policies.size());
		assertNull(listResult.getMarker());
		assertEquals("testPolicy2", policies.get(0).getPolicyName());
		System.out.println(listResult.getMarker());
		System.out.println(policies.get(0).getPolicyName());
		System.out.println(policies.get(0).getPolicyArn());
		System.out.println(policies.get(0).getDescription());
		System.out.println(policies.get(0).getScope());
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(arn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setPolicyArn(arn2);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(arn2);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * group绑定2个策略 listAttachedGroupPolicies时设置maxItems为1 marker返回值为list数据的最后一条
	 * 
	 */
	@Test
	public void listAttachedGroupPolicies_maxItem1_marker_ok_test() {
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("desc test");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();

		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("desc test2");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String arn2 = result2.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setPolicyArn(arn2);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		// listAttachedGroupPolicies
		ListAttachedGroupPoliciesRequest request = new ListAttachedGroupPoliciesRequest();
		request.setGroupName(groupName);
		request.setMaxItems(1);
		ListAttachedGroupPoliciesResult listResult = client.listAttachedGroupPolicies(request);
		List<AttachedPolicy> policies = listResult.getAttachedPolicies();
		assertEquals(1, policies.size());
		assertEquals("policy|34e5k5ig79cjf|testgroup|Local|testpolicy", listResult.getMarker());
		System.out.println(listResult.getMarker());
		System.out.println(policies.get(0).getPolicyName());
		System.out.println(policies.get(0).getPolicyArn());
		System.out.println(policies.get(0).getDescription());
		System.out.println(policies.get(0).getScope());
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(arn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setPolicyArn(arn2);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(arn2);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listAttachedGroupPolicies_maxItems1000_ok_test2() {
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("desc test");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();

		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("desc test2");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String arn2 = result2.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setPolicyArn(arn2);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		// listAttachedGroupPolicies
		ListAttachedGroupPoliciesRequest request = new ListAttachedGroupPoliciesRequest();
		request.setGroupName(groupName);
		request.setMaxItems(1000);
		ListAttachedGroupPoliciesResult listResult = client.listAttachedGroupPolicies(request);
		List<AttachedPolicy> policies = listResult.getAttachedPolicies();
		assertEquals(2, policies.size());
		System.out.println("---------------policy info-------------");
		for (AttachedPolicy policy2 : policies) {
			System.out.println(policy2.getPolicyName());
			System.out.println(policy2.getPolicyArn());
			System.out.println(policy2.getDescription());
			System.out.println(policy2.getScope());
		}
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(arn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setPolicyArn(arn2);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(arn2);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listAttachedGroupPolicies_maxItems1001_fail_test() {
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("desc test");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String arn = result.getPolicy().getArn();

		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("desc test2");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String arn2 = result2.getPolicy().getArn();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(arn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setPolicyArn(arn2);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		// listAttachedGroupPolicies
		ListAttachedGroupPoliciesRequest request = new ListAttachedGroupPoliciesRequest();
		request.setGroupName(groupName);
		request.setMaxItems(1001);
		try {
			client.listAttachedGroupPolicies(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
					e.getMessage());
		}
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(arn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setPolicyArn(arn2);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(arn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(arn2);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * user没有绑定策略
	 */
	@Test
	public void listAttachedUserPolicies_ok_test() {
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		// listAttachedUserPolicies
		ListAttachedUserPoliciesRequest request = new ListAttachedUserPoliciesRequest();
		request.setUserName(userName);
		ListAttachedUserPoliciesResult listResult = client.listAttachedUserPolicies(request);
		assertFalse(listResult.getIsTruncated());
		assertEquals(0, listResult.getAttachedPolicies().size());
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
	}

	/**
	 * user绑定1个策略
	 */
	@Test
	public void listAttachedUserPolicies_ok_test2() {
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		// listAttachedUserPolicies
		ListAttachedUserPoliciesRequest request = new ListAttachedUserPoliciesRequest();
		request.setUserName(userName);
		ListAttachedUserPoliciesResult listResult = client.listAttachedUserPolicies(request);
		List<AttachedPolicy> policies = listResult.getAttachedPolicies();
		assertFalse(listResult.getIsTruncated());
		assertEquals(1, policies.size());
		AttachedPolicy policy = policies.get(0);
		assertEquals(policyArn, policy.getPolicyArn());
		assertEquals(name, policy.getPolicyName());
		assertEquals("test desc 测试！", policy.getDescription());
		assertEquals("Local", policy.getScope());
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * user绑定2个策略
	 */
	@Test
	public void listAttachedUserPolicies_ok_test3() {
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();

		createPolicyRequest.setPolicyName("testPolicy2");
		createPolicyRequest.setDescription("test desc 测试2！");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String policyArn2 = result2.getPolicy().getArn();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setPolicyArn(policyArn2);
		client.attachUserPolicy(attachUserPolicyRequest);
		// listAttachedUserPolicies
		ListAttachedUserPoliciesRequest request = new ListAttachedUserPoliciesRequest();
		request.setUserName(userName);
		ListAttachedUserPoliciesResult listResult = client.listAttachedUserPolicies(request);
		List<AttachedPolicy> policies = listResult.getAttachedPolicies();
		assertFalse(listResult.getIsTruncated());
		assertEquals(2, policies.size());
		System.out.println("---------user policies info-------------");
		for (AttachedPolicy policy : policies) {
			System.out.println(policy.getPolicyArn());
			System.out.println(policy.getPolicyName());
			System.out.println(policy.getDescription());
			System.out.println(policy.getScope());
		}
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setPolicyArn(policyArn2);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * user绑定2个policy marker指定testPolicy，listAttachedUserPolicies返回testPolicy2
	 */
	@Test
	public void listAttachedUserPolicies_marker_ok_test() {
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();

		createPolicyRequest.setPolicyName("testPolicy2");
		createPolicyRequest.setDescription("test desc 测试2！");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String policyArn2 = result2.getPolicy().getArn();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setPolicyArn(policyArn2);
		client.attachUserPolicy(attachUserPolicyRequest);
		// listAttachedUserPolicies
		ListAttachedUserPoliciesRequest request = new ListAttachedUserPoliciesRequest();
		request.setUserName(userName);
		request.setMarker("policy|34e5k5ig79cjf|sdktestuser|Local|testpolicy");
		ListAttachedUserPoliciesResult listResult = client.listAttachedUserPolicies(request);
		List<AttachedPolicy> policies = listResult.getAttachedPolicies();
		assertFalse(listResult.getIsTruncated());
		assertEquals(1, policies.size());
		assertEquals(null, listResult.getMarker());
		System.out.println(listResult.getMarker());
		System.out.println("---------user policies info-------------");
		for (AttachedPolicy policy : policies) {
			System.out.println(policy.getPolicyArn());
			System.out.println(policy.getPolicyName());
			System.out.println(policy.getDescription());
			System.out.println(policy.getScope());
		}
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setPolicyArn(policyArn2);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * user绑定2个策略 maxItems设置为1 返回的marker为list数据的最后一条：testPolicy
	 */
	@Test
	public void listAttachedUserPolicies_maxItems1_marker_ok_test3() {
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();

		createPolicyRequest.setPolicyName("testPolicy2");
		createPolicyRequest.setDescription("test desc 测试2！");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String policyArn2 = result2.getPolicy().getArn();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setPolicyArn(policyArn2);
		client.attachUserPolicy(attachUserPolicyRequest);
		// listAttachedUserPolicies
		ListAttachedUserPoliciesRequest request = new ListAttachedUserPoliciesRequest();
		request.setUserName(userName);
		request.setMaxItems(1);
		ListAttachedUserPoliciesResult listResult = client.listAttachedUserPolicies(request);
		List<AttachedPolicy> policies = listResult.getAttachedPolicies();
		assertTrue(listResult.getIsTruncated());
		assertEquals(1, policies.size());
		assertTrue(listResult.getIsTruncated());
		assertEquals("policy|34e5k5ig79cjf|sdktestuser|Local|testpolicy", listResult.getMarker());
		System.out.println(listResult.getMarker());
		System.out.println("---------user policies info-------------");
		for (AttachedPolicy policy : policies) {
			System.out.println(policy.getPolicyArn());
			System.out.println(policy.getPolicyName());
			System.out.println(policy.getDescription());
			System.out.println(policy.getScope());
		}
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setPolicyArn(policyArn2);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * user绑定2个策略 maxItems设置为1000 返回的marker为null
	 */
	@Test
	public void listAttachedUserPolicies_maxItems1000_marker_ok_test() {
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();

		createPolicyRequest.setPolicyName("testPolicy2");
		createPolicyRequest.setDescription("test desc 测试2！");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String policyArn2 = result2.getPolicy().getArn();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setPolicyArn(policyArn2);
		client.attachUserPolicy(attachUserPolicyRequest);
		// listAttachedUserPolicies
		ListAttachedUserPoliciesRequest request = new ListAttachedUserPoliciesRequest();
		request.setUserName(userName);
		request.setMaxItems(1000);
		ListAttachedUserPoliciesResult listResult = client.listAttachedUserPolicies(request);
		List<AttachedPolicy> policies = listResult.getAttachedPolicies();
		assertEquals(2, policies.size());
		assertFalse(listResult.getIsTruncated());
		assertNull(listResult.getMarker());
		System.out.println("---------user policies info-------------");
		for (AttachedPolicy policy : policies) {
			System.out.println(policy.getPolicyArn());
			System.out.println(policy.getPolicyName());
			System.out.println(policy.getDescription());
			System.out.println(policy.getScope());
		}
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setPolicyArn(policyArn2);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	@Test
	public void listAttachedUserPolicies_maxItems1001_fail_test() {
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();

		createPolicyRequest.setPolicyName("testPolicy2");
		createPolicyRequest.setDescription("test desc 测试2！");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String policyArn2 = result2.getPolicy().getArn();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setPolicyArn(policyArn2);
		client.attachUserPolicy(attachUserPolicyRequest);
		// listAttachedUserPolicies
		ListAttachedUserPoliciesRequest request = new ListAttachedUserPoliciesRequest();
		request.setUserName(userName);
		request.setMaxItems(1001);
		try {
			client.listAttachedUserPolicies(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
					e.getMessage());
		}
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setPolicyArn(policyArn2);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	@Test
	public void listAttachedUserPolicies_maxItems0_fail_test() {
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();

		createPolicyRequest.setPolicyName("testPolicy2");
		createPolicyRequest.setDescription("test desc 测试2！");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String policyArn2 = result2.getPolicy().getArn();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setPolicyArn(policyArn2);
		client.attachUserPolicy(attachUserPolicyRequest);
		// listAttachedUserPolicies
		ListAttachedUserPoliciesRequest request = new ListAttachedUserPoliciesRequest();
		request.setUserName(userName);
		request.setMaxItems(0);
		try {
			client.listAttachedUserPolicies(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",
					e.getMessage());
		}
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setPolicyArn(policyArn2);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	@Test
	public void listAttachedUserPolicies_nullUserName_ok_test() {
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();

		createPolicyRequest.setPolicyName("testPolicy2");
		createPolicyRequest.setDescription("test desc 测试2！");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String policyArn2 = result2.getPolicy().getArn();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setPolicyArn(policyArn2);
		client.attachUserPolicy(attachUserPolicyRequest);
		// listAttachedUserPolicies
		ListAttachedUserPoliciesRequest request = new ListAttachedUserPoliciesRequest();
		request.setUserName(null);
		request.setMaxItems(1);
		try {
			client.listAttachedUserPolicies(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setPolicyArn(policyArn2);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	@Test
	public void listAttachedUserPolicies_noUserName_ok_test() {
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		client.createUser(cu);
		// createPolicy 2个
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();

		createPolicyRequest.setPolicyName("testPolicy2");
		createPolicyRequest.setDescription("test desc 测试2！");
		CreatePolicyResult result2 = client.createPolicy(createPolicyRequest);
		String policyArn2 = result2.getPolicy().getArn();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setPolicyArn(policyArn2);
		client.attachUserPolicy(attachUserPolicyRequest);
		// listAttachedUserPolicies
		ListAttachedUserPoliciesRequest request = new ListAttachedUserPoliciesRequest();
		request.setUserName("noUserxx");
		request.setMaxItems(1);
		try {
			client.listAttachedUserPolicies(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("The user with name noUserxx cannot be found.", e.getMessage());
		}
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setPolicyArn(policyArn2);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * 策略没有附加到任何组、用户
	 * 
	 */
	@Test
	public void listEntitiesForPolicy_noAttach_ok_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(policyArn);
		ListEntitiesForPolicyResult listResult = client.listEntitiesForPolicy(request);
		List<PolicyGroup> groups = listResult.getPolicyGroups();
		List<PolicyUser> users = listResult.getPolicyUsers();
		assertEquals(0, groups.size());
		assertEquals(0, users.size());
		assertFalse(listResult.getIsTruncated());
	}

	/**
	 * policy只附加到1个组上
	 * 
	 */
	@Test
	public void listEntitiesForPolicy_attachGroup_ok_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		String groupId = group.getGroupId();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(policyArn);
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(policyArn);
		ListEntitiesForPolicyResult listResult = client.listEntitiesForPolicy(request);
		List<PolicyGroup> groups = listResult.getPolicyGroups();
		List<PolicyUser> users = listResult.getPolicyUsers();
		assertEquals(1, groups.size());
		assertEquals(0, users.size());
		assertFalse(listResult.getIsTruncated());
		assertEquals(groupName, groups.get(0).getGroupName());
		assertEquals(groupId, groups.get(0).getGroupId());
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(policyArn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 策略被附加到一个user上
	 * 
	 */
	@Test
	public void listEntitiesForPolicy_attachUser_ok_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		CreateUserResult userResult = client.createUser(cu);
		String userId = userResult.getUser().getUserId();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);

		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(policyArn);
		ListEntitiesForPolicyResult listResult = client.listEntitiesForPolicy(request);
		List<PolicyGroup> groups = listResult.getPolicyGroups();
		List<PolicyUser> users = listResult.getPolicyUsers();
		assertEquals(0, groups.size());
		assertEquals(1, users.size());
		assertEquals(userName, users.get(0).getUserName());
		assertEquals(userId, users.get(0).getUserId());
		assertFalse(listResult.getIsTruncated());
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * 策略被附加到一个group、一个user上
	 * 
	 */
	@Test
	public void listEntitiesForPolicy_attachGroupUser_ok_test1() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		CreateUserResult userResult = client.createUser(cu);
		String userId = userResult.getUser().getUserId();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		String groupId = group.getGroupId();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(policyArn);
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(policyArn);
		ListEntitiesForPolicyResult listResult = client.listEntitiesForPolicy(request);
		List<PolicyGroup> groups = listResult.getPolicyGroups();
		List<PolicyUser> users = listResult.getPolicyUsers();
		assertEquals(1, groups.size());
		assertEquals(1, users.size());
		assertEquals(groupName, groups.get(0).getGroupName());
		assertEquals(groupId, groups.get(0).getGroupId());
		assertEquals(userName, users.get(0).getUserName());
		assertEquals(userId, users.get(0).getUserId());
		assertFalse(listResult.getIsTruncated());
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(policyArn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
	}

	/**
	 * 策略被附加到2个group、2个user上
	 * 
	 */
	@Test
	public void listEntitiesForPolicy_attachGroupUser_ok_test2() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		System.out.println("policyArn===" + policyArn);
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		CreateUserResult userResult = client.createUser(cu);
		String userId = userResult.getUser().getUserId();
		cu.setUserName("sdktestuser2");
		CreateUserResult userResult2 = client.createUser(cu);
		String userId2 = userResult2.getUser().getUserId();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setUserName("sdktestuser2");
		client.attachUserPolicy(attachUserPolicyRequest);
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		String groupId = group.getGroupId();

		createGroupRequest.setGroupName("testGroup2");
		CreateGroupResult createResult2 = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group2 = createResult2.getGroup();
		assertEquals("testGroup2", group2.getGroupName());
		String groupId2 = group2.getGroupId();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(policyArn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setGroupName("testGroup2");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(policyArn);
		ListEntitiesForPolicyResult listResult = client.listEntitiesForPolicy(request);
		List<PolicyGroup> groups = listResult.getPolicyGroups();
		List<PolicyUser> users = listResult.getPolicyUsers();
		assertEquals(2, groups.size());
		assertEquals(2, users.size());
		assertFalse(listResult.getIsTruncated());
		System.out.println("-----group info-----------");
		for (PolicyGroup gp : groups) {
			System.out.println(gp.getGroupId());
			System.out.println(gp.getGroupName());
		}
		System.out.println("---------user info----------");
		for (PolicyUser user : users) {
			System.out.println(user.getUserId());
			System.out.println(user.getUserName());
		}
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setUserName("sdktestuser2");
		client.detachUserPolicy(detachUserPolicyRequest);
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(policyArn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setGroupName("testGroup2");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listEntitiesForPolicy_attachGroupUser_EntityFilter_ok_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		CreateUserResult userResult = client.createUser(cu);
		String userId = userResult.getUser().getUserId();
		cu.setUserName("sdktestuser2");
		CreateUserResult userResult2 = client.createUser(cu);
		String userId2 = userResult2.getUser().getUserId();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setUserName("sdktestuser2");
		client.attachUserPolicy(attachUserPolicyRequest);
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		String groupId = group.getGroupId();

		createGroupRequest.setGroupName("testGroup2");
		CreateGroupResult createResult2 = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group2 = createResult2.getGroup();
		assertEquals("testGroup2", group2.getGroupName());
		String groupId2 = group2.getGroupId();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(policyArn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setGroupName("testGroup2");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(policyArn);
		request.setEntityFilter("User");
		ListEntitiesForPolicyResult listResult = client.listEntitiesForPolicy(request);
		List<PolicyGroup> groups = listResult.getPolicyGroups();
		List<PolicyUser> users = listResult.getPolicyUsers();
		assertEquals(0, groups.size());
		assertEquals(2, users.size());
		assertFalse(listResult.getIsTruncated());
		System.out.println("---------user info----------");
		for (PolicyUser user : users) {
			System.out.println(user.getUserId());
			System.out.println(user.getUserName());
		}
		request.setEntityFilter("Group");
		listResult = client.listEntitiesForPolicy(request);
		groups = listResult.getPolicyGroups();
		users = listResult.getPolicyUsers();
		assertEquals(2, groups.size());
		assertEquals(0, users.size());
		assertFalse(listResult.getIsTruncated());
		System.out.println("-----group info-----------");
		for (PolicyGroup gp : groups) {
			System.out.println(gp.getGroupId());
			System.out.println(gp.getGroupName());
		}
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setUserName("sdktestuser2");
		client.detachUserPolicy(detachUserPolicyRequest);
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(policyArn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setGroupName("testGroup2");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listEntitiesForPolicy_invalidEntityFilter_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		CreateUserResult userResult = client.createUser(cu);
		String userId = userResult.getUser().getUserId();
		cu.setUserName("sdktestuser2");
		CreateUserResult userResult2 = client.createUser(cu);
		String userId2 = userResult2.getUser().getUserId();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setUserName("sdktestuser2");
		client.attachUserPolicy(attachUserPolicyRequest);
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		String groupId = group.getGroupId();

		createGroupRequest.setGroupName("testGroup2");
		CreateGroupResult createResult2 = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group2 = createResult2.getGroup();
		assertEquals("testGroup2", group2.getGroupName());
		String groupId2 = group2.getGroupId();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(policyArn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setGroupName("testGroup2");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(policyArn);
		request.setEntityFilter("User1");
		try {
			client.listEntitiesForPolicy(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value 'User1' at 'entityFilter' failed to satisfy constraint: Member must satisfy enum value set: [User, Group]",
					e.getMessage());
		}
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setUserName("sdktestuser2");
		client.detachUserPolicy(detachUserPolicyRequest);
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(policyArn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setGroupName("testGroup2");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listEntitiesForPolicy_noArn_fail_test() {
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf:policy/testPolicy");
		try {
			client.listEntitiesForPolicy(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(404, e.getStatusCode());
			assertEquals("NoSuchEntity", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals("Policy arn:ctyun:iam::34e5k5ig79cjf:policy/testPolicy does not exist or is not attachable.",
					e.getMessage());
		}
	}

	@Test
	public void listEntitiesForPolicy_nullArn_fail_test() {
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(null);
		try {
			client.listEntitiesForPolicy(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value null at 'policyArn' failed to satisfy constraint: Member must not be null",
					e.getMessage());
		}
	}

	@Test
	public void listEntitiesForPolicy_maxItems0_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		CreateUserResult userResult = client.createUser(cu);
		String userId = userResult.getUser().getUserId();
		cu.setUserName("sdktestuser2");
		CreateUserResult userResult2 = client.createUser(cu);
		String userId2 = userResult2.getUser().getUserId();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setUserName("sdktestuser2");
		client.attachUserPolicy(attachUserPolicyRequest);
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		String groupId = group.getGroupId();

		createGroupRequest.setGroupName("testGroup2");
		CreateGroupResult createResult2 = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group2 = createResult2.getGroup();
		assertEquals("testGroup2", group2.getGroupName());
		String groupId2 = group2.getGroupId();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(policyArn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setGroupName("testGroup2");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(policyArn);
		request.setMaxItems(0);
		try {
			client.listEntitiesForPolicy(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",
					e.getMessage());
		}
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setUserName("sdktestuser2");
		client.detachUserPolicy(detachUserPolicyRequest);
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(policyArn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setGroupName("testGroup2");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listEntitiesForPolicy_maxItems1_ok_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		CreateUserResult userResult = client.createUser(cu);
		String userId = userResult.getUser().getUserId();
		cu.setUserName("sdktestuser2");
		CreateUserResult userResult2 = client.createUser(cu);
		String userId2 = userResult2.getUser().getUserId();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setUserName("sdktestuser2");
		client.attachUserPolicy(attachUserPolicyRequest);
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		String groupId = group.getGroupId();

		createGroupRequest.setGroupName("testGroup2");
		CreateGroupResult createResult2 = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group2 = createResult2.getGroup();
		assertEquals("testGroup2", group2.getGroupName());
		String groupId2 = group2.getGroupId();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(policyArn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setGroupName("testGroup2");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(policyArn);
		request.setMaxItems(1);
		ListEntitiesForPolicyResult listResult = client.listEntitiesForPolicy(request);
		List<PolicyGroup> groups = listResult.getPolicyGroups();
		List<PolicyUser> users = listResult.getPolicyUsers();
		assertEquals(1, groups.size());
		assertEquals(0, users.size());
		assertTrue(listResult.getIsTruncated());
		System.out.println("Marker===" + listResult.getMarker());
		assertEquals("entity|34e5k5ig79cjf|Local|testpolicy|Group|testgroup", listResult.getMarker());
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setUserName("sdktestuser2");
		client.detachUserPolicy(detachUserPolicyRequest);
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(policyArn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setGroupName("testGroup2");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listEntitiesForPolicy_maxItems2_ok_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		CreateUserResult userResult = client.createUser(cu);
		String userId = userResult.getUser().getUserId();
		cu.setUserName("sdktestuser2");
		CreateUserResult userResult2 = client.createUser(cu);
		String userId2 = userResult2.getUser().getUserId();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setUserName("sdktestuser2");
		client.attachUserPolicy(attachUserPolicyRequest);
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		String groupId = group.getGroupId();

		createGroupRequest.setGroupName("testGroup2");
		CreateGroupResult createResult2 = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group2 = createResult2.getGroup();
		assertEquals("testGroup2", group2.getGroupName());
		String groupId2 = group2.getGroupId();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(policyArn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setGroupName("testGroup2");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(policyArn);
		request.setMaxItems(2);
		ListEntitiesForPolicyResult listResult = client.listEntitiesForPolicy(request);
		List<PolicyGroup> groups = listResult.getPolicyGroups();
		List<PolicyUser> users = listResult.getPolicyUsers();
		assertEquals(2, groups.size());
		assertEquals(0, users.size());
		assertTrue(listResult.getIsTruncated());
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setUserName("sdktestuser2");
		client.detachUserPolicy(detachUserPolicyRequest);
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(policyArn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setGroupName("testGroup2");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listEntitiesForPolicy_maxItems3_ok_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		CreateUserResult userResult = client.createUser(cu);
		String userId = userResult.getUser().getUserId();
		cu.setUserName("sdktestuser2");
		CreateUserResult userResult2 = client.createUser(cu);
		String userId2 = userResult2.getUser().getUserId();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setUserName("sdktestuser2");
		client.attachUserPolicy(attachUserPolicyRequest);
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		String groupId = group.getGroupId();

		createGroupRequest.setGroupName("testGroup2");
		CreateGroupResult createResult2 = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group2 = createResult2.getGroup();
		assertEquals("testGroup2", group2.getGroupName());
		String groupId2 = group2.getGroupId();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(policyArn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setGroupName("testGroup2");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(policyArn);
		request.setMaxItems(3);
		ListEntitiesForPolicyResult listResult = client.listEntitiesForPolicy(request);
		List<PolicyGroup> groups = listResult.getPolicyGroups();
		List<PolicyUser> users = listResult.getPolicyUsers();
		assertEquals(2, groups.size());
		assertEquals(1, users.size());
		assertTrue(listResult.getIsTruncated());
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setUserName("sdktestuser2");
		client.detachUserPolicy(detachUserPolicyRequest);
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(policyArn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setGroupName("testGroup2");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listEntitiesForPolicy_maxItems1000_ok_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		CreateUserResult userResult = client.createUser(cu);
		String userId = userResult.getUser().getUserId();
		cu.setUserName("sdktestuser2");
		CreateUserResult userResult2 = client.createUser(cu);
		String userId2 = userResult2.getUser().getUserId();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setUserName("sdktestuser2");
		client.attachUserPolicy(attachUserPolicyRequest);
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		String groupId = group.getGroupId();

		createGroupRequest.setGroupName("testGroup2");
		CreateGroupResult createResult2 = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group2 = createResult2.getGroup();
		assertEquals("testGroup2", group2.getGroupName());
		String groupId2 = group2.getGroupId();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(policyArn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setGroupName("testGroup2");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(policyArn);
		request.setMaxItems(1000);
		ListEntitiesForPolicyResult listResult = client.listEntitiesForPolicy(request);
		List<PolicyGroup> groups = listResult.getPolicyGroups();
		List<PolicyUser> users = listResult.getPolicyUsers();
		assertEquals(2, groups.size());
		assertEquals(2, users.size());
		assertFalse(listResult.getIsTruncated());
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setUserName("sdktestuser2");
		client.detachUserPolicy(detachUserPolicyRequest);
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(policyArn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setGroupName("testGroup2");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listEntitiesForPolicy_maxItems1001_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		CreateUserResult userResult = client.createUser(cu);
		String userId = userResult.getUser().getUserId();
		cu.setUserName("sdktestuser2");
		CreateUserResult userResult2 = client.createUser(cu);
		String userId2 = userResult2.getUser().getUserId();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setUserName("sdktestuser2");
		client.attachUserPolicy(attachUserPolicyRequest);
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		String groupId = group.getGroupId();

		createGroupRequest.setGroupName("testGroup2");
		CreateGroupResult createResult2 = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group2 = createResult2.getGroup();
		assertEquals("testGroup2", group2.getGroupName());
		String groupId2 = group2.getGroupId();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(policyArn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setGroupName("testGroup2");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(policyArn);
		request.setMaxItems(1001);
		try {
			client.listEntitiesForPolicy(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
					e.getMessage());
		}
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setUserName("sdktestuser2");
		client.detachUserPolicy(detachUserPolicyRequest);
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(policyArn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setGroupName("testGroup2");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listEntitiesForPolicy_AccessDenied_fail_test() {
		// createPolicy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = client.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// createUser
		String userName = "sdktestuser";
		CreateUserRequest cu = new CreateUserRequest(userName);
		CreateUserResult userResult = client.createUser(cu);
		String userId = userResult.getUser().getUserId();
		cu.setUserName("sdktestuser2");
		CreateUserResult userResult2 = client.createUser(cu);
		String userId2 = userResult2.getUser().getUserId();
		// attachUserPolicy
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn(policyArn);
		attachUserPolicyRequest.setUserName(userName);
		client.attachUserPolicy(attachUserPolicyRequest);
		attachUserPolicyRequest.setUserName("sdktestuser2");
		client.attachUserPolicy(attachUserPolicyRequest);
		// createGroup
		String groupName = "testGroup";
		CreateGroupRequest createGroupRequest = new CreateGroupRequest();
		createGroupRequest.setGroupName(groupName);
		CreateGroupResult createResult = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group = createResult.getGroup();
		assertEquals(groupName, group.getGroupName());
		String groupId = group.getGroupId();

		createGroupRequest.setGroupName("testGroup2");
		CreateGroupResult createResult2 = client.createGroup(createGroupRequest);
		com.amazonaws.services.identitymanagement.model.Group group2 = createResult2.getGroup();
		assertEquals("testGroup2", group2.getGroupName());
		String groupId2 = group2.getGroupId();
		// attachGroupPolicy
		AttachGroupPolicyRequest attachGroupPolicyRequest = new AttachGroupPolicyRequest();
		attachGroupPolicyRequest.setGroupName(groupName);
		attachGroupPolicyRequest.setPolicyArn(policyArn);
		client.attachGroupPolicy(attachGroupPolicyRequest);

		attachGroupPolicyRequest.setGroupName("testGroup2");
		client.attachGroupPolicy(attachGroupPolicyRequest);
		// listEntitiesForPolicy
		ListEntitiesForPolicyRequest request = new ListEntitiesForPolicyRequest();
		request.setPolicyArn(policyArn);
		try {
			client2.listEntitiesForPolicy(request);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(403, e.getStatusCode());
			assertEquals("AccessDenied", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"User: arn:ctyun:iam::2khdzd8yb0pkw:user/user2@oos.com is not authorized to perform: iam:ListEntitiesForPolicy on resource: arn:ctyun:iam::34e5k5ig79cjf:policy/testPolicy.",
					e.getMessage());
		}
		// detachUserPolicy
		DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest();
		detachUserPolicyRequest.setUserName(userName);
		detachUserPolicyRequest.setPolicyArn(policyArn);
		client.detachUserPolicy(detachUserPolicyRequest);
		detachUserPolicyRequest.setUserName("sdktestuser2");
		client.detachUserPolicy(detachUserPolicyRequest);
		// DetachGroupPolicy
		DetachGroupPolicyRequest detachGroupPolicyRequest = new DetachGroupPolicyRequest();
		detachGroupPolicyRequest.setGroupName(groupName);
		detachGroupPolicyRequest.setPolicyArn(policyArn);
		client.detachGroupPolicy(detachGroupPolicyRequest);
		detachGroupPolicyRequest.setGroupName("testGroup2");
		client.detachGroupPolicy(detachGroupPolicyRequest);
		// deleteUser
		DeleteUserRequest deleteUserRequest = new DeleteUserRequest(userName);
		client.deleteUser(deleteUserRequest);
		deleteUserRequest.setUserName("sdktestuser2");
		client.deleteUser(deleteUserRequest);
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		client.deletePolicy(deletePolicyRequest);
		// deleteGroup
		DeleteGroupRequest deleteGroupRequest = new DeleteGroupRequest(groupName);
		client.deleteGroup(deleteGroupRequest);
		deleteGroupRequest.setGroupName("testGroup2");
		client.deleteGroup(deleteGroupRequest);
	}

	@Test
	public void listPolicies_ok_test() {
		// 根用户root1@test.com创建1个policy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = rootClient.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// 子用户user1@oos.com创建policy
		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("test desc 测试2！");
		result = client.createPolicy(createPolicyRequest);
		String policyArn2 = result.getPolicy().getArn();
		// listPolies
		ListPoliciesRequest listPoliciesRequest = new ListPoliciesRequest();
		ListPoliciesResult listResult = client.listPolicies(listPoliciesRequest);
		List<Policy> polies = listResult.getPolicies();
		for (Policy py : polies) {
			System.out.println(py.getUpdateDate());
			System.out.println(py.getPolicyId());
			System.out.println(py.getIsAttachable());
			System.out.println(py.getPolicyName());
			System.out.println(py.getAttachmentCount());
			System.out.println(py.getArn());
			System.out.println(py.getCreateDate());
			System.out.println(py.getScope());
			System.out.println(py.getDescription());
		}
		assertEquals(3, polies.size()); // 包含初始化时创建的sdkPolicy
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		rootClient.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	@Test
	public void listPolicies_OnlyAttachedTrue_ok_test() {
		// 根用户root1@test.com创建1个policy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = rootClient.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// 子用户user1@oos.com创建policy
		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("test desc 测试2！");
		result = client.createPolicy(createPolicyRequest);
		String policyArn2 = result.getPolicy().getArn();
		// listPolies
		ListPoliciesRequest listPoliciesRequest = new ListPoliciesRequest();
		listPoliciesRequest.setOnlyAttached(true);
		ListPoliciesResult listResult = client.listPolicies(listPoliciesRequest);
		List<Policy> polies = listResult.getPolicies();
		for (Policy py : polies) {
			System.out.println(py.getUpdateDate());
			System.out.println(py.getPolicyId());
			System.out.println(py.getIsAttachable());
			System.out.println(py.getPolicyName());
			System.out.println(py.getAttachmentCount());
			System.out.println(py.getArn());
			System.out.println(py.getCreateDate());
			System.out.println(py.getScope());
			System.out.println(py.getDescription());
		}
		assertEquals(1, polies.size()); // 初始化时创建的sdkPolicy
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		rootClient.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	@Test
	public void listPolicies_OnlyAttachedFalse_ok_test() {
		// 根用户root1@test.com创建1个policy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = rootClient.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// 子用户user1@oos.com创建policy
		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("test desc 测试2！");
		result = client.createPolicy(createPolicyRequest);
		String policyArn2 = result.getPolicy().getArn();
		// listPolies
		ListPoliciesRequest listPoliciesRequest = new ListPoliciesRequest();
		listPoliciesRequest.setOnlyAttached(false);
		ListPoliciesResult listResult = client.listPolicies(listPoliciesRequest);
		List<Policy> polies = listResult.getPolicies();
		for (Policy py : polies) {
			System.out.println(py.getUpdateDate());
			System.out.println(py.getPolicyId());
			System.out.println(py.getIsAttachable());
			System.out.println(py.getPolicyName());
			System.out.println(py.getAttachmentCount());
			System.out.println(py.getArn());
			System.out.println(py.getCreateDate());
			System.out.println(py.getScope());
			System.out.println(py.getDescription());
		}
		assertEquals(3, polies.size()); // 包含初始化时创建的sdkPolicy
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		rootClient.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * policyName模糊匹配
	 * 
	 */
	@Test
	public void listPolicies_policyName_ok_test() {
		// 根用户root1@test.com创建1个policy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = rootClient.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// 子用户user1@oos.com创建policy
		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("test desc 测试2！");
		result = client.createPolicy(createPolicyRequest);
		String policyArn2 = result.getPolicy().getArn();
		// listPolies
		ListPoliciesRequest listPoliciesRequest = new ListPoliciesRequest();
		listPoliciesRequest.setPolicyName("test");
		ListPoliciesResult listResult = client.listPolicies(listPoliciesRequest);
		List<Policy> polies = listResult.getPolicies();
		for (Policy py : polies) {
			System.out.println(py.getUpdateDate());
			System.out.println(py.getPolicyId());
			System.out.println(py.getIsAttachable());
			System.out.println(py.getPolicyName());
			assertTrue(py.getPolicyName().contains("test"));
			System.out.println(py.getAttachmentCount());
			System.out.println(py.getArn());
			System.out.println(py.getCreateDate());
			System.out.println(py.getScope());
			System.out.println(py.getDescription());
		}
		assertEquals(2, polies.size()); // 包含初始化时创建的sdkPolicy
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		rootClient.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * policyName模糊匹配
	 * 
	 */
	@Test
	public void listPolicies_policyName_noMatch_ok_test() {
		// 根用户root1@test.com创建1个policy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = rootClient.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// 子用户user1@oos.com创建policy
		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("test desc 测试2！");
		result = client.createPolicy(createPolicyRequest);
		String policyArn2 = result.getPolicy().getArn();
		// listPolies
		ListPoliciesRequest listPoliciesRequest = new ListPoliciesRequest();
		listPoliciesRequest.setPolicyName("testX");
		ListPoliciesResult listResult = client.listPolicies(listPoliciesRequest);
		List<Policy> polies = listResult.getPolicies();
		for (Policy py : polies) {
			System.out.println(py.getUpdateDate());
			System.out.println(py.getPolicyId());
			System.out.println(py.getIsAttachable());
			System.out.println(py.getPolicyName());
			assertTrue(py.getPolicyName().contains("testX"));
			System.out.println(py.getAttachmentCount());
			System.out.println(py.getArn());
			System.out.println(py.getCreateDate());
			System.out.println(py.getScope());
			System.out.println(py.getDescription());
		}
		assertEquals(0, polies.size()); // 包含初始化时创建的sdkPolicy
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		rootClient.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * root1@test.com账户下共有3个policy maxItems设置为1
	 */
	@Test
	public void listPolicies_policyName_maxItems1_marker_ok_test() {
		// 根用户root1@test.com创建1个policy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = rootClient.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// 子用户user1@oos.com创建policy
		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("test desc 测试2！");
		result = client.createPolicy(createPolicyRequest);
		String policyArn2 = result.getPolicy().getArn();
		// listPolies
		ListPoliciesRequest listPoliciesRequest = new ListPoliciesRequest();
		listPoliciesRequest.setMaxItems(1);
		ListPoliciesResult listResult = client.listPolicies(listPoliciesRequest);
		List<Policy> polies = listResult.getPolicies();
		for (Policy py : polies) {
			System.out.println(py.getUpdateDate());
			System.out.println(py.getPolicyId());
			System.out.println(py.getIsAttachable());
			System.out.println(py.getPolicyName());
			System.out.println(py.getAttachmentCount());
			System.out.println(py.getArn());
			System.out.println(py.getCreateDate());
			System.out.println(py.getScope());
			System.out.println(py.getDescription());
		}
		assertEquals(1, polies.size()); // 包含初始化时创建的sdkPolicy
		assertTrue(listResult.getIsTruncated());
		System.out.println("marker=" + listResult.getMarker());
		assertEquals("34e5k5ig79cjf|sdkpolicy", listResult.getMarker());
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		rootClient.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	/**
	 * root1@test.com账户下共有3个policy maxItems设置为1000
	 */
	@Test
	public void listPolicies_policyName_maxItems1000_ok_test() {
		// 根用户root1@test.com创建1个policy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = rootClient.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// 子用户user1@oos.com创建policy
		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("test desc 测试2！");
		result = client.createPolicy(createPolicyRequest);
		String policyArn2 = result.getPolicy().getArn();
		// listPolies
		ListPoliciesRequest listPoliciesRequest = new ListPoliciesRequest();
		listPoliciesRequest.setMaxItems(1000);
		ListPoliciesResult listResult = client.listPolicies(listPoliciesRequest);
		List<Policy> polies = listResult.getPolicies();
		for (Policy py : polies) {
			System.out.println(py.getUpdateDate());
			System.out.println(py.getPolicyId());
			System.out.println(py.getIsAttachable());
			System.out.println(py.getPolicyName());
			System.out.println(py.getAttachmentCount());
			System.out.println(py.getArn());
			System.out.println(py.getCreateDate());
			System.out.println(py.getScope());
			System.out.println(py.getDescription());
		}
		assertEquals(3, polies.size()); // 包含初始化时创建的sdkPolicy
		assertFalse(listResult.getIsTruncated());
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		rootClient.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	@Test
	public void listPolicies_policyName_maxItems0_fail_test() {
		// 根用户root1@test.com创建1个policy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = rootClient.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// 子用户user1@oos.com创建policy
		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("test desc 测试2！");
		result = client.createPolicy(createPolicyRequest);
		String policyArn2 = result.getPolicy().getArn();
		// listPolies
		ListPoliciesRequest listPoliciesRequest = new ListPoliciesRequest();
		listPoliciesRequest.setMaxItems(0);
		try {
			client.listPolicies(listPoliciesRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: Member must have value greater than or equal to 1",
					e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		rootClient.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	@Test
	public void listPolicies_policyName_maxItems1001_fail_test() {
		// 根用户root1@test.com创建1个policy
		String name = "testPolicy";
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setPolicyName(name);
		createPolicyRequest.setDescription("test desc 测试！");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		CreatePolicyResult result = rootClient.createPolicy(createPolicyRequest);
		String policyArn = result.getPolicy().getArn();
		// 子用户user1@oos.com创建policy
		String name2 = "testPolicy2";
		createPolicyRequest.setPolicyName(name2);
		createPolicyRequest.setDescription("test desc 测试2！");
		result = client.createPolicy(createPolicyRequest);
		String policyArn2 = result.getPolicy().getArn();
		// listPolies
		ListPoliciesRequest listPoliciesRequest = new ListPoliciesRequest();
		listPoliciesRequest.setMaxItems(1001);
		try {
			client.listPolicies(listPoliciesRequest);
			fail();
		} catch (AmazonS3Exception e) {
			assertEquals(400, e.getStatusCode());
			assertEquals("ValidationError", e.getErrorCode());
			System.out.println(e.getMessage());
			assertEquals(
					"1 validation error detected: Value '1001' at 'maxItems' failed to satisfy constraint: Member must have value less than or equal to 1000",
					e.getMessage());
		}
		// deletePolicy
		DeletePolicyRequest deletePolicyRequest = new DeletePolicyRequest();
		deletePolicyRequest.setPolicyArn(policyArn);
		rootClient.deletePolicy(deletePolicyRequest);
		deletePolicyRequest.setPolicyArn(policyArn2);
		client.deletePolicy(deletePolicyRequest);
	}

	@Test
	public void getAccountSummary_ok_test() {
		// 创建用户
//		String userName = "sdktestuser";
//		CreateUserRequest cu = new CreateUserRequest();
//		cu.setUserName(userName);
//		CreateUserResult userResult = client.createUser(cu);
//		assertEquals(userName, userResult.getUser().getUserName());
//		String userArn = userResult.getUser().getArn();

		GetAccountSummaryRequest getAccountSummaryRequest = new GetAccountSummaryRequest();
		GetAccountSummaryResult getResult = client.getAccountSummary(getAccountSummaryRequest);
		Map<String, Integer> map = getResult.getSummaryMap();
		Set<String> keySet = map.keySet();
		System.out.println(map.toString());
		assertTrue(keySet.contains("Policies"));
		assertTrue(keySet.contains("GroupsPerUserQuota"));
		assertTrue(keySet.contains("AttachedPoliciesPerUserQuota"));
		assertTrue(keySet.contains("Users"));
		assertTrue(keySet.contains("PoliciesQuota"));
//		assertTrue(keySet.contains("AccountMFAEnabled"));
		assertTrue(keySet.contains("AccessKeysPerUserQuota"));
		assertTrue(keySet.contains("AttachedPoliciesPerGroupQuota"));
		assertTrue(keySet.contains("Groups"));
		assertTrue(keySet.contains("UsersQuota"));
		assertTrue(keySet.contains("MFADevices"));
		assertTrue(keySet.contains("MFADevicesInUse"));
		assertTrue(keySet.contains("AccountAccessKeysPresent"));
		assertTrue(keySet.contains("GroupsQuota"));
	}

	public static String byteBufferToString(ByteBuffer buffer) {
		CharBuffer charBuffer = null;
		try {
			Charset charset = Charset.forName("UTF-8");
//			CharsetDecoder decoder = charset.newDecoder();
////			charBuffer = decoder.decode(buffer);
//			charBuffer = decoder.decode(buffer.asReadOnlyBuffer());
//			buffer.flip();
			return charset.decode(buffer).toString();
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}
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


//		@Test
	public void createRootUser() throws Exception {
		IAMTestUtils.TrancateTable("iam-policy-wtz");
		IAMTestUtils.TrancateTable("oos-aksk-wtz2");
		IAMTestUtils.TrancateTable("oos-owner-wtz");
		IAMTestUtils.TrancateTable("iam-user-wtz");
		IAMTestUtils.TrancateTable("iam-accountSummary-wtz");
		MetaClient metaClient = MetaClient.getGlobalClient();
		// 创建根用户1
		owner.email = ownerName;
		owner.setPwd("123456");
		owner.maxAKNum = 10;
		owner.displayName = "测试根用户1";
		owner.bucketCeilingNum = 10;
		metaClient.ownerInsertForTest(owner);

		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.accessKey = AK;
		aksk.setSecretKey(SK);
		aksk.isPrimary = 1;
		metaClient.akskInsert(aksk);

		// 创建根用户2
		owner2.email = ownerName2;
		owner2.setPwd("123456");
		owner2.maxAKNum = 10;
		owner2.displayName = "测试根用户2";
		owner2.bucketCeilingNum = 10;
		metaClient.ownerInsertForTest(owner2);

		AkSkMeta aksk2 = new AkSkMeta(owner2.getId());
		aksk2.accessKey = AK2;
		aksk2.setSecretKey(SK2);
		aksk2.isPrimary = 1;
		metaClient.akskInsert(aksk2);
	}

	/**
	 * 创建两个子用户，并赋予全部权限
	 * 
	 * @throws IOException
	 */
//	@Test
	public void createSubUser() throws IOException {
		// 创建subUser1
		cn.ctyun.oos.iam.server.entity.User user1 = new cn.ctyun.oos.iam.server.entity.User();
		user1.accountId = accountId;
		user1.userName = subUser1;
		user1.userId = "Test1Abc";
		user1.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user1);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}

		AkSkMeta aksk = new AkSkMeta(owner.getId());
		aksk.isRoot = 0;
		aksk.userId = user1.userId;
		aksk.userName = subUser1;
		aksk.accessKey = ak1;
		aksk.setSecretKey(sk1);
		metaClient.akskInsert(aksk);
		user1.accessKeys = new ArrayList<>();
		user1.userName = subUser1;
		user1.accessKeys.add(aksk.accessKey);
		HBaseUtils.put(user1);
		// 创建subUser2
		cn.ctyun.oos.iam.server.entity.User user2 = new cn.ctyun.oos.iam.server.entity.User();
		user2.accountId = accountId2;
		user2.userName = subUser2;
		user2.userId = "test2Abc";
		user2.createDate = System.currentTimeMillis();
		try {
			boolean success = HBaseUtils.checkAndCreate(user2);
			assertTrue(success);
		} catch (IOException e) {
			e.printStackTrace();
		}
		AkSkMeta aksk2 = new AkSkMeta(owner2.getId());
		aksk2.isRoot = 0;
		aksk2.userId = user2.userId;
		aksk2.userName = subUser2;
		aksk2.accessKey = ak2;
		aksk2.setSecretKey(sk2);
		metaClient.akskInsert(aksk2);
		user2.accessKeys = new ArrayList<>();
		user2.userName = subUser2;
		user2.accessKeys.add(aksk2.accessKey);
		HBaseUtils.put(user2);
	}

//	@Test
	public void createAndAttachPolicy() throws IOException {
		// 创建策略
		CreatePolicyRequest createPolicyRequest = new CreatePolicyRequest();
		createPolicyRequest.setDescription("For Sdk Test");
		createPolicyRequest.setPolicyName("sdkPolicy");
		String policyDocument = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924571\",\"Statement\":[{\"Sid\":\"1569805924571_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::34e5k5ig79cjf:*\"}]}";
		createPolicyRequest.setPolicyDocument(policyDocument);
		rootClient.createPolicy(createPolicyRequest);
		// 分配策略到用户
		AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest();
		attachUserPolicyRequest.setPolicyArn("arn:ctyun:iam::34e5k5ig79cjf:policy/sdkPolicy");
		attachUserPolicyRequest.setUserName(subUser1);
		rootClient.attachUserPolicy(attachUserPolicyRequest);

		// 创建策略
		CreatePolicyRequest createPolicyRequest2 = new CreatePolicyRequest();
		createPolicyRequest2.setDescription("For Sdk Test2");
		createPolicyRequest2.setPolicyName("sdkPolicy2");
		String policyDocument2 = "{\"Version\":\"2012-10-17\",\"Id\":\"1569805924572\",\"Statement\":[{\"Sid\":\"1569805924572_1\",\"Effect\":\"Allow\",\"NotAction\":\"oos:PutObject\",\"Resource\":\"arn:ctyun:iam::2khdzd8yb0pkw:*\"}]}";
		createPolicyRequest2.setPolicyDocument(policyDocument2);
		rootClient2.createPolicy(createPolicyRequest2);
		// 分配策略到用户
		AttachUserPolicyRequest attachUserPolicyRequest2 = new AttachUserPolicyRequest();
		attachUserPolicyRequest2.setPolicyArn("arn:ctyun:iam::2khdzd8yb0pkw:policy/sdkPolicy2");
		attachUserPolicyRequest2.setUserName(subUser2);
		rootClient2.attachUserPolicy(attachUserPolicyRequest2);
	}

}
